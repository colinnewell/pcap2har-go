package reader

import (
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net/http"

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

func (h *HTTPConversationReaders) ReadRequest(r io.Reader, a, b gopacket.Flow) {
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
					}
				}
				address := ConversationAddress{IP: a.Reverse(), Port: b.Reverse()}
				con := len(h.conversations[address]) - 1
				if con >= 0 {
					c := h.conversations[address][con]
					c.Response = res
					c.ResponseBody = body
					h.conversations[address][con] = c
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
			})
			if err != nil {
				return
			}
		}
		alt.Reset()
	}
}
