package reader

import (
	"bufio"
	"compress/gzip"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/colinnewell/pcap-cli/tcp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type HTTPConversationReaders struct {
	mu            sync.Mutex
	conversations map[ConversationAddress][]Conversation
}

type ConversationAddress struct {
	IP, Port gopacket.Flow
}
type Conversation struct {
	Address      ConversationAddress
	Request      *http.Request
	RequestBody  []byte
	Response     *http.Response
	ResponseBody []byte
	RequestSeen  []time.Time
	ResponseSeen []time.Time
	// FastCGI info if present
	Errors []string
}

func New() *HTTPConversationReaders {
	conversations := make(map[ConversationAddress][]Conversation)
	return &HTTPConversationReaders{
		conversations: conversations,
	}
}

type streamDecoder func(*tcp.SavePointReader, *tcp.TimeCaptureReader, gopacket.Flow, gopacket.Flow) error

func drain(spr *tcp.SavePointReader, _ *tcp.TimeCaptureReader, _, _ gopacket.Flow) error {
	tcpreader.DiscardBytesToEOF(spr)
	return nil
}

// ReadStream tries to read tcp connections and extract HTTP conversations.
func (h *HTTPConversationReaders) ReadStream(r tcp.Stream, a, b gopacket.Flow, completed chan interface{}) {
	t := tcp.NewTimeCaptureReader(r)
	spr := tcp.NewSavePointReader(t)
	decoders := []streamDecoder{
		h.ReadHTTPRequest,
		h.ReadHTTPResponse,
		h.ReadFCGIRequest,
		drain,
	}
	for {
		for i, decode := range decoders {
			err := decode(spr, t, a, b)
			if err == nil {
				break
			}
			if err == io.EOF {
				return
			} else if err != nil {
				// don't need to restore before the last one
				if i+1 < len(decoders) {
					// can discard the save point on the final restore
					spr.Restore(i < len(decoders))
				}
			}
		}
		t.Reset()
	}
}

// ReadHTTPResponse try to read the stream as an HTTP response.
func (h *HTTPConversationReaders) ReadHTTPResponse(spr *tcp.SavePointReader, t *tcp.TimeCaptureReader, a, b gopacket.Flow) error {
	buf := bufio.NewReader(spr)

	res, err := http.ReadResponse(buf, nil)
	if err != nil {
		return err
	}

	spr.SavePoint()
	defer res.Body.Close()

	var reader io.ReadCloser
	if res.Header.Get("Content-Encoding") == "gzip" {
		reader, err = gzip.NewReader(res.Body)
		if err != nil {
			// just get it raw
			reader = res.Body
		} else {
			defer reader.Close()
		}
	} else {
		reader = res.Body
	}

	body, err := ioutil.ReadAll(reader)
	// unexpected EOF reading trailer seems to indicate truncated stream when
	// dealing with chunked encdoing.  If we fall back to not reading it, we
	// still have the same basic output, just with all the chunking arterfacts.
	if err != nil && err.Error() != "http: unexpected EOF reading trailer" {
		spr.Restore(true)
		buf = bufio.NewReader(spr)
		body, err = ioutil.ReadAll(buf)
		if err != nil {
			log.Println("Got an error trying to read it raw, let's just discard")
			tcpreader.DiscardBytesToEOF(buf)
		}
	}
	h.addResponse(a, b, res, body, t.Seen())
	return err
}

// ReadHTTPRequest try to read the stream as an HTTP request.
func (h *HTTPConversationReaders) ReadHTTPRequest(spr *tcp.SavePointReader, t *tcp.TimeCaptureReader, a, b gopacket.Flow) error {
	spr.SavePoint()
	buf := bufio.NewReader(spr)

	req, err := http.ReadRequest(buf)
	if err != nil {
		return err
	}

	spr.SavePoint()
	defer req.Body.Close()
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		spr.Restore(true)
		buf = bufio.NewReader(spr)
		body, err = ioutil.ReadAll(buf)
		if err != nil {
			log.Println("Got an error trying to read it raw, let's just discard")
			tcpreader.DiscardBytesToEOF(buf)
		}
	}

	h.addRequest(a, b, req, body, t.Seen())
	return err
}

func (h *HTTPConversationReaders) addRequest(a, b gopacket.Flow, req *http.Request, body []byte, seen []time.Time) {
	address := ConversationAddress{IP: a, Port: b}
	h.mu.Lock()
	defer h.mu.Unlock()
	conversations := h.conversations[address]
	for n := 0; n < len(conversations); n++ {
		c := conversations[n]
		if conversations[n].Request == nil {
			c.Request = req
			c.RequestBody = body
			c.RequestSeen = seen
			h.conversations[address][n] = c
			return
		}
	}
	h.conversations[address] = append(h.conversations[address], Conversation{
		Address:     address,
		Request:     req,
		RequestBody: body,
		RequestSeen: seen,
	})
}

func (h *HTTPConversationReaders) addErrorToResponse(a, b gopacket.Flow, errString string) {
	h.updateResponse(a, b, func(c *Conversation) {
		c.Errors = append(c.Errors, errString)
	})
}

func (h *HTTPConversationReaders) addResponse(a, b gopacket.Flow, res *http.Response, body []byte, seen []time.Time) {
	h.updateResponse(a, b, func(c *Conversation) {
		c.Response = res
		c.ResponseBody = body
		c.ResponseSeen = seen
	})
}

func (h *HTTPConversationReaders) updateResponse(a, b gopacket.Flow, update func(*Conversation)) {
	address := ConversationAddress{IP: a.Reverse(), Port: b.Reverse()}
	h.mu.Lock()
	defer h.mu.Unlock()
	conversations := h.conversations[address]
	if conversations == nil {
		c := Conversation{
			Address: address,
		}
		update(&c)
		h.conversations[address] = append(h.conversations[address], c)
		return
	}
	for n := 0; n < len(conversations); n++ {
		c := conversations[n]
		if conversations[n].Response == nil {
			update(&c)
			h.conversations[address][n] = c
			break
		}
		// FIXME: should think about what we do when we don't find
		// the other side of the conversation.
	}
}
