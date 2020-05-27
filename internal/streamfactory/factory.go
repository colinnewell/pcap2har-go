package streamfactory

import (
	"github.com/colinnewell/pcap2har-go/internal/reader"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
	"github.com/google/gopacket/tcpassembly/tcpreader"
)

type HTTPStreamFactory struct {
	Reader reader.HTTPConversationReaders
}

func (f *HTTPStreamFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
	r := tcpreader.NewReaderStream()
	go f.Reader.ReadRequest(&r, a, b)
	return &r
}
