package streamfactory

import (
	"github.com/colinnewell/pcap2har-go/internal/reader"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

type HTTPStreamFactory struct {
	Reader reader.HTTPConversationReaders
}

func (f *HTTPStreamFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
	r := reader.NewReaderStream()
	go f.Reader.ReadStream(&r, a, b)
	return &r
}
