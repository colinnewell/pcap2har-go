package streamfactory

import (
	"sync"

	"github.com/colinnewell/pcap2har-go/internal/reader"

	"github.com/google/gopacket"
	"github.com/google/gopacket/tcpassembly"
)

type ConversationReader interface {
	ReadStream(r reader.ReaderStream, a, b gopacket.Flow)
}

type HTTPStreamFactory struct {
	Reader ConversationReader
	wg     sync.WaitGroup
}

func (f *HTTPStreamFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
	r := reader.NewReaderStream()
	f.wg.Add(1)
	go func() {
		f.Reader.ReadStream(&r, a, b)
		f.wg.Done()
	}()
	return &r
}

func (f *HTTPStreamFactory) Wait() {
	f.wg.Wait()
}
