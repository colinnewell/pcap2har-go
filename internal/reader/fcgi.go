package reader

import (
	"io/ioutil"
	"net/http"

	"github.com/google/gopacket"

	"github.com/colinnewell/pcap2har-go/internal/go/fcgi"
)

type FCGIInfoGatherer struct {
	a, b gopacket.Flow
	t    *TimeCaptureReader
	h    *HTTPConversationReaders
}

func NewFCGIInfoGatherer(h *HTTPConversationReaders, t *TimeCaptureReader, a, b gopacket.Flow) *FCGIInfoGatherer {
	return &FCGIInfoGatherer{
		a: a,
		b: b,
		h: h,
		t: t,
	}
}

func (d *FCGIInfoGatherer) ErrorInfo(string) {
}

func (d *FCGIInfoGatherer) RequestInfo(req *http.Request) {
	defer req.Body.Close()
	body, _ := ioutil.ReadAll(req.Body)
	d.h.addRequest(d.a, d.b, req, body, d.t.Seen())
}

func (d *FCGIInfoGatherer) ResponseInfo(resp *http.Response, body []byte) {
	d.h.addResponse(d.a, d.b, resp, body, d.t.Seen())
}
func (d *FCGIInfoGatherer) ReturnValue(int) {
}

func (h *HTTPConversationReaders) ReadFCGIRequest(spr *SavePointReader, t *TimeCaptureReader, a, b gopacket.Flow) error {
	// try to product an HTTP request from the stream
	c := fcgi.NewChild(NewFCGIInfoGatherer(h, t, a, b))
	return c.ReadRequest(spr)
}
