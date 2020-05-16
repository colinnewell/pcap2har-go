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
	address       conversationAddress
	request       *http.Request
	request_body  []byte
	response      *http.Response
	response_body []byte
}

var conversations map[conversationAddress]conversation

func (f *httpStreamFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	go printRequests(&r, a, b)
	return &r
}

func printRequests(r io.Reader, a, b gopacket.Flow) {
	var alt bytes.Buffer
	tee := io.TeeReader(r, &alt)
	buf := bufio.NewReader(tee)

	for {
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
				body, err := ioutil.ReadAll(res.Body)
				if err != nil {
					return
				}
				address := conversationAddress{ip: a.Reverse(), port: b.Reverse()}
				c := conversations[address]
				c.response = res
				c.response_body = body
				conversations[address] = c
			}
		} else {
			address := conversationAddress{ip: a, port: b}
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				return
			}
			conversations[address] = conversation{
				address:      address,
				request:      req,
				request_body: body,
			}
		}
	}
}

func main() {
	files := os.Args[1:]

	if len(files) == 0 {
		log.Fatal("Must specify filename")
	}

	conversations = make(map[conversationAddress]conversation)

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
	for _, v := range conversations {
		// FIXME: plug into the har structure
		var reqheaders []Header
		for k, values := range v.request.Header {
			for _, v := range values {
				reqheaders = append(reqheaders, Header{Name: k, Value: v})
			}
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
		req := RequestInfo{
			Cookies:     cookieInfo,
			Headers:     reqheaders,
			Method:      v.request.Method,
			URL:         v.request.URL.String(),
			QueryString: queryString,
			Content: ContentInfo{
				Size:     len(v.request_body),
				MimeType: mimeType,
				Text:     string(v.request_body),
			},
		}
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
		resp := ResponseInfo{
			Content: ContentInfo{
				Size:     len(v.response_body),
				MimeType: mimeType,
				Text:     string(v.response_body),
			},
			Headers:     headers,
			HTTPVersion: v.response.Proto,
			StatusText:  v.response.Status,
			Status:      v.response.StatusCode,
		}
		entry := Entry{
			Request:  req,
			Response: resp,
			// FIXME: add connection info
		}
		har.Log.Entries = append(har.Log.Entries, entry)
		//fmt.Println(v.address.ip, v.address.port)
		//fmt.Println(v.request)
		//fmt.Println(v.request_body)
		//fmt.Println(v.response)
		//fmt.Println(v.response_body)
	}

	bytes, err := json.Marshal(har)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(bytes))
}
