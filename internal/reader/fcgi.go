package reader

import (
	"github.com/google/gopacket"
)

func (h *HTTPConversationReaders) ReadFCGIRequest(spr *SavePointReader, t *TimeCaptureReader, a, b gopacket.Flow) error {
	// try to product an HTTP request from the stream
	//h.addRequest(a, b, req, body, t.Seen())
	return nil
}
