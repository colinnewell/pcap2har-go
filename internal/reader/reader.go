package reader

import (
	"bufio"
	"bytes"
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

// ReadRequest tries to read tcp connections and extract HTTP conversations.
func (h *HTTPConversationReaders) ReadRequest(r *ReaderStream, a, b gopacket.Flow) {
	var alt bytes.Buffer

	t := NewTimeCaptureReader(r)

	for {
		tee := io.TeeReader(t, &alt)
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
				defer res.Body.Close()
				body, err := ioutil.ReadAll(res.Body)
				if err != nil {
					rawBody := io.MultiReader(&alt, buf)
					body, err = ioutil.ReadAll(rawBody)
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
				}
				// FIXME: should think about what we do when we don't find
				// the other side of the conversation.
				if err != nil {
					return
				}
			}
		} else {
			address := ConversationAddress{IP: a, Port: b}
			alt.Reset()
			body, err := ioutil.ReadAll(req.Body)
			if err != nil {
				rawBody := io.MultiReader(&alt, buf)
				body, err = ioutil.ReadAll(rawBody)
				if err != nil {
					log.Println("Got an error trying to read it raw, let's just discard")
					tcpreader.DiscardBytesToEOF(buf)
				}
			}
			h.conversations[address] = append(h.conversations[address], Conversation{
				Address:     address,
				Request:     req,
				RequestBody: body,
				RequestSeen: t.Seen(),
			})
			if err != nil {
				return
			}
		}
		alt.Reset()
		t.Reset()
	}
}
