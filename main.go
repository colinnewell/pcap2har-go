package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type Creator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Page struct {
	StartedDateTime time.Time `json:"startedDateTime"`
	ID              string    `json:"id"`
	Title           string    `json:"title"`
	PageTimings     struct {
		OnContentLoad float64     `json:"onContentLoad"`
		OnLoad        interface{} `json:"onLoad"`
	} `json:"pageTimings"`
}

type Header KeyValues

type Cookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Expires  time.Time `json:"expires"`
	HTTPOnly bool      `json:"httpOnly"`
	Secure   bool      `json:"secure"`
}

type RequestInfo struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []Header    `json:"headers"`
	QueryString []KeyValues `json:"queryString"`
	Cookies     []Cookie    `json:"cookies"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
	Content     ContentInfo `json:"content"`
}

type ContentInfo struct {
	MimeType string `json:"mimeType"`
	Size     int    `json:"size"`
	Text     string `json:"text"`
}

type KeyValues struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ResponseInfo struct {
	Status       int           `json:"status"`
	StatusText   string        `json:"statusText"`
	HTTPVersion  string        `json:"httpVersion"`
	Headers      []Header      `json:"headers"`
	Cookies      []interface{} `json:"cookies"`
	Content      ContentInfo   `json:"content"`
	RedirectURL  string        `json:"redirectURL"`
	HeadersSize  int           `json:"headersSize"`
	BodySize     int           `json:"bodySize"`
	TransferSize int           `json:"_transferSize"`
}

type Entry struct {
	StartedDateTime time.Time    `json:"startedDateTime"`
	Time            float64      `json:"time"`
	Request         RequestInfo  `json:"request"`
	Response        ResponseInfo `json:"response"`
	ServerIPAddress string       `json:"serverIPAddress"`
	Connection      string       `json:"connection,omitempty"`
}

type Har struct {
	Log struct {
		Version string  `json:"version"`
		Creator Creator `json:"creator"`
		Pages   []Page  `json:"pages"`
		Entries []Entry `json:"entries"`
	} `json:"log"`
}

var har Har

type httpStreamFactory struct{}

type conversationAddress struct {
	ip, port gopacket.Flow
}
type conversation struct {
	address      conversationAddress
	request      *http.Request
	requestBody  []byte
	response     *http.Response
	responseBody []byte
}

var conversations map[conversationAddress][]conversation

func (f *httpStreamFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	go printRequests(&r, a, b)
	return &r
}

func printRequests(r io.Reader, a, b gopacket.Flow) {
	var alt bytes.Buffer

	for {
		tee := io.TeeReader(r, &alt)
		buf := bufio.NewReader(tee)
		if req, err := http.ReadRequest(buf); err == io.EOF {
			return
		} else if err != nil {
			m := io.MultiReader(&alt, buf)
			buf := bufio.NewReader(m)
			if res, err := http.ReadResponse(buf, nil); err == io.EOF {
				return
			} else if err != nil {
				// meh, guess it's not for us.
			} else {
				alt.Reset()
				body, err := ioutil.ReadAll(res.Body)
				if err != nil {
					rawBody := io.MultiReader(&alt, buf)
					body, err = ioutil.ReadAll(rawBody)
					if err != nil {
						log.Println("Got an error trying to read it raw, let's just discard")

						tcpreader.DiscardBytesToEOF(buf)
						log.Println(a, b, "++++++++++++", err)
					}
				}
				address := conversationAddress{ip: a.Reverse(), port: b.Reverse()}
				c := conversations[address][len(conversations[address])-1]
				c.response = res
				c.responseBody = body
				conversations[address][len(conversations[address])-1] = c
			}
		} else {
			address := conversationAddress{ip: a, port: b}
			alt.Reset()
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				rawBody := io.MultiReader(&alt, buf)
				body, err = ioutil.ReadAll(rawBody)
				if err != nil {
					log.Println("Got an error trying to read it raw, let's just discard")

					tcpreader.DiscardBytesToEOF(buf)
					log.Println(a, b, "++++++++++++", err)
				}
			}
			conversations[address] = append(conversations[address], conversation{
				address:     address,
				request:     req,
				requestBody: body,
			})
		}
		alt.Reset()
	}
}

func main() {
	files := os.Args[1:]

	if len(files) == 0 {
		log.Fatal("Must specify filename")
	}

	conversations = make(map[conversationAddress][]conversation)

	streamFactory := &httpStreamFactory{}
	streamPool := tcpassembly.NewStreamPool(streamFactory)
	assembler := tcpassembly.NewAssembler(streamPool)

	for _, filename := range files {
		if handle, err := pcap.OpenOffline(filename); err != nil {
			log.Fatal(err)
		} else {
			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

			for packet := range packetSource.Packets() {
				// NOTE: just pushing all TCP through it on the basis it might
				// be http.
				if tcp, ok := packet.TransportLayer().(*layers.TCP); ok {
					assembler.AssembleWithTimestamp(
						packet.NetworkLayer().NetworkFlow(),
						tcp, packet.Metadata().Timestamp)
				}
			}
		}
	}

	assembler.FlushAll()
	//fmt.Printf("Found %d connections\n", connections)
	for _, c := range conversations {
		for _, v := range c {
			var reqheaders []Header
			for k, values := range v.request.Header {
				for _, v := range values {
					reqheaders = append(reqheaders, Header{Name: k, Value: v})
				}
			}
			if v.request.Host != "" {
				reqheaders = append(reqheaders, Header{
					Name: "Host", Value: v.request.Host,
				})
			}
			cookies := v.request.Cookies()
			cookieInfo := make([]Cookie, len(cookies))
			for i, c := range cookies {
				cookieInfo[i] = Cookie{
					Name:     c.Name,
					Value:    c.Value,
					Expires:  c.Expires,
					HTTPOnly: c.HttpOnly,
					Secure:   c.Secure,
				}
			}
			var queryString []KeyValues
			for k, values := range v.request.URL.Query() {
				for _, v := range values {
					queryString = append(queryString, KeyValues{Name: k, Value: v})
				}
			}
			var mimeType string
			mimeTypes, ok := v.request.Header["Content-Type"]
			if ok {
				mimeType = mimeTypes[0]
			}
			// for some reason host isn't hooked up
			v.request.URL.Host = v.request.Host
			if v.request.TLS == nil {
				v.request.URL.Scheme = "http"
			} else {
				v.request.URL.Scheme = "https"
			}
			req := RequestInfo{
				Cookies:     cookieInfo,
				Headers:     reqheaders,
				Method:      v.request.Method,
				URL:         v.request.URL.String(),
				QueryString: queryString,
				Content: ContentInfo{
					Size:     len(v.requestBody),
					MimeType: mimeType,
					Text:     string(v.requestBody),
				},
			}
			resp := ResponseInfo{}
			if v.response != nil {
				mimeTypes, ok = v.response.Header["Content-Type"]
				if ok {
					mimeType = mimeTypes[0]
				}
				var headers []Header
				for k, values := range v.response.Header {
					for _, v := range values {
						headers = append(headers, Header{Name: k, Value: v})
					}
				}
				resp = ResponseInfo{
					Content: ContentInfo{
						Size:     len(v.responseBody),
						MimeType: mimeType,
						Text:     string(v.responseBody),
					},
					Headers:     headers,
					HTTPVersion: v.response.Proto,
					StatusText:  v.response.Status,
					Status:      v.response.StatusCode,
				}
			}
			entry := Entry{
				Request:  req,
				Response: resp,
			}
			har.Log.Entries = append(har.Log.Entries, entry)
		}
	}

	bytes, err := json.Marshal(har)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(bytes))
}
