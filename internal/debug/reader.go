package debug

import (
	"time"

	"github.com/google/gopacket"

	"github.com/colinnewell/pcap2har-go/internal/reader"
	"github.com/colinnewell/pcap2har-go/internal/streamfactory"
)

type DebugConversationReader struct {
	reader streamfactory.ConversationReader
	file   string
}

func New(cr streamfactory.ConversationReader, file string) *DebugConversationReader {
	return &DebugConversationReader{reader: cr, file: file}
}

func (d *DebugConversationReader) ReadStream(r reader.ReaderStream, a, b gopacket.Flow) {
	// FIXME: do a defer on our writers here?
	drs := DebugReaderStream{r: r}
	d.reader.ReadStream(drs, a, b)
	drs.Dump(d.file)
}

func (d *DebugConversationReader) Close() {
	// dump out the files?
}

type DebugReaderStream struct {
	r reader.ReaderStream
}

func (d DebugReaderStream) Read(p []byte) (n int, err error) {
	return d.r.Read(p)
}

func (d DebugReaderStream) Seen() (time.Time, error) {
	return d.r.Seen()
}

func (d DebugReaderStream) Dump(file string) {
}
