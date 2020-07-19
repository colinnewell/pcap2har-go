package reader

import (
	"io/ioutil"
	"net/http"

	"github.com/google/gopacket"
)

func (h *HTTPConversationReaders) ReadFCGIRequest(spr *SavePointReader, t *TimeCaptureReader, a, b gopacket.Flow) error {
	// try to product an HTTP request from the stream
	//h.addRequest(a, b, req, body, t.Seen())
	c := fcgi.NewChild(func(req *http.Request) {
		defer req.Body.Close()
		body, _ := ioutil.ReadAll(req.Body)
		h.addRequest(a, b, req, body, t.Seen())
	})
	c.ReadRequest(spr)
	return nil
}
