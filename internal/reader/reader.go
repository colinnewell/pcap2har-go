package reader

import (
	"bufio"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"sync"
	"time"

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
}

func New() HTTPConversationReaders {
	conversations := make(map[ConversationAddress][]Conversation)
	return HTTPConversationReaders{
		conversations: conversations,
	}
}

func (h *HTTPConversationReaders) GetConversations() []Conversation {
	var conversations []Conversation
	for _, c := range h.conversations {
		conversations = append(conversations, c...)
	}
	return conversations
}

type ReaderStream interface {
	Read(p []byte) (n int, err error)
	Seen() (time.Time, error)
}

type StreamInterpreter func(*SavePointReader, *TimeCaptureReader, gopacket.Flow, gopacket.Flow) error

func drain(spr *SavePointReader, _ *TimeCaptureReader, _, _ gopacket.Flow) error {
	tcpreader.DiscardBytesToEOF(spr)
	return nil
}

// ReadStream tries to read tcp connections and extract HTTP conversations.
func (h *HTTPConversationReaders) ReadStream(r ReaderStream, a, b gopacket.Flow) {
	t := NewTimeCaptureReader(r)
	spr := NewSavePointReader(t)
	for {
		for _, decode := range []StreamInterpreter{
			h.ReadHTTPRequest,
			h.ReadHTTPResponse,
			h.ReadFCGIRequest,
			drain,
		} {
			err := decode(spr, t, a, b)
			if err == nil {
				break
			}
			if err == io.EOF {
				return
			} else if err != nil {
				// FIXME: if this is the last one, set to true
				spr.Restore(false)
			}
		}
		t.Reset()
	}
}

// ReadHTTPResponse try to read the stream as an HTTP response.
func (h *HTTPConversationReaders) ReadHTTPResponse(spr *SavePointReader, t *TimeCaptureReader, a, b gopacket.Flow) error {
	buf := bufio.NewReader(spr)

	res, err := http.ReadResponse(buf, nil)
	if err != nil {
		return err
	}

	spr.SavePoint()
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
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
func (h *HTTPConversationReaders) ReadHTTPRequest(spr *SavePointReader, t *TimeCaptureReader, a, b gopacket.Flow) error {
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

func (h *HTTPConversationReaders) addResponse(a, b gopacket.Flow, res *http.Response, body []byte, seen []time.Time) {
	address := ConversationAddress{IP: a.Reverse(), Port: b.Reverse()}
	h.mu.Lock()
	defer h.mu.Unlock()
	conversations := h.conversations[address]
	if conversations == nil {
		h.conversations[address] = append(h.conversations[address], Conversation{
			Address:      address,
			Response:     res,
			ResponseBody: body,
			ResponseSeen: seen,
		})
		return
	}
	for n := 0; n < len(conversations); n++ {
		c := conversations[n]
		if conversations[n].Response == nil {
			c.Response = res
			c.ResponseBody = body
			c.ResponseSeen = seen
			h.conversations[address][n] = c
			break
		}
		// FIXME: should think about what we do when we don't find
		// the other side of the conversation.
	}
}
