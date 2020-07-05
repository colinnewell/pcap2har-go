package reader

import (
	"bufio"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type HTTPConversationReaders struct {
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

// ReadStream tries to read tcp connections and extract HTTP conversations.
func (h *HTTPConversationReaders) ReadStream(r ReaderStream, a, b gopacket.Flow) {
	t := NewTimeCaptureReader(r)
	spr := NewSavePointReader(t)
	for {
		err := h.ReadHTTPRequest(spr, t, a, b)
		if err == io.EOF {
			return
		} else if err != nil {
			spr.Restore(true)
			err := h.ReadHTTPResponse(spr, t, a, b)
			if err != nil {
				return
			}
		}
		t.Reset()
	}
}

func (h *HTTPConversationReaders) ReadHTTPResponse(spr *SavePointReader, t *TimeCaptureReader, a, b gopacket.Flow) error {
	buf := bufio.NewReader(spr)

	res, err := http.ReadResponse(buf, nil)
	if err == io.EOF {
		return err
	} else if err != nil {
		return nil
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
	address := ConversationAddress{IP: a.Reverse(), Port: b.Reverse()}
	conversations := h.conversations[address]
	for n := 0; n < len(conversations); n++ {
		c := conversations[n]
		if conversations[n].Response == nil {
			c.Response = res
			c.ResponseBody = body
			c.ResponseSeen = t.Seen()
			h.conversations[address][n] = c
			break
		}
		// FIXME: should think about what we do when we don't find
		// the other side of the conversation.
	}
	return err
}
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

	address := ConversationAddress{IP: a, Port: b}
	h.conversations[address] = append(h.conversations[address], Conversation{
		Address:     address,
		Request:     req,
		RequestBody: body,
		RequestSeen: t.Seen(),
	})
	return err
}
