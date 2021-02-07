package reader

import (
	"errors"
	"io"
	"time"

	"github.com/google/gopacket/tcpassembly"
)

// clone of gopacket/tcpassembly/tcpreader/reader.go that allows timing info to be extracted

// TCPReaderStream implements both tcpassembly.Stream and io.Reader.  You can use it
// as a building block to make simple, easy stream handlers.
//
// IMPORTANT:  If you use a TCPReaderStream, you MUST read ALL BYTES from it,
// quickly.  Not reading available bytes will block TCP stream reassembly.  It's
// a common pattern to do this by starting a goroutine in the factory's New
// method:
//
//  type myStreamHandler struct {
//  	r TCPReaderStream
//  }
//  func (m *myStreamHandler) run() {
//  	// Do something here that reads all of the TCPReaderStream, or your assembly
//  	// will block.
//  	fmt.Println(tcpreader.DiscardBytesToEOF(&m.r))
//  }
//  func (f *myStreamFactory) New(a, b gopacket.Flow) tcpassembly.Stream {
//  	s := &myStreamHandler{}
//  	go s.run()
//  	// Return the TCPReaderStream as the stream that assembly should populate.
//  	return &s.r
//  }
type TCPReaderStream struct {
	reassembled  chan []tcpassembly.Reassembly
	current      []tcpassembly.Reassembly
	done         chan bool
	closed       bool
	lossReported bool
	first        bool
	initiated    bool
	ReaderStreamOptions
}

// ReaderStreamOptions provides user-resettable options for a TCPReaderStream.
type ReaderStreamOptions struct {
	// LossErrors determines whether this stream will return
	// ReaderStreamDataLoss errors from its Read function whenever it
	// determines data has been lost.
	LossErrors bool
}

// NewReaderStream returns a new TCPReaderStream object.
func NewReaderStream() TCPReaderStream {
	r := TCPReaderStream{
		reassembled: make(chan []tcpassembly.Reassembly),
		done:        make(chan bool),
		first:       true,
		initiated:   true,
	}
	return r
}

// Reassembled implements tcpassembly.Stream's Reassembled function.
func (r *TCPReaderStream) Reassembled(reassembly []tcpassembly.Reassembly) {
	if !r.initiated {
		panic("TCPReaderStream not created via NewReaderStream")
	}
	r.reassembled <- reassembly
	<-r.done
}

// ReassemblyComplete implements tcpassembly.Stream's ReassemblyComplete function.
func (r *TCPReaderStream) ReassemblyComplete() {
	close(r.reassembled)
	close(r.done)
}

// stripEmpty strips empty reassembly slices off the front of its current set of
// slices.
func (r *TCPReaderStream) stripEmpty() {
	for len(r.current) > 0 && len(r.current[0].Bytes) == 0 {
		r.current = r.current[1:]
		r.lossReported = false
	}
}

// DataLost is returned by the TCPReaderStream's Read function when it encounters
// a Reassembly with Skip != 0.
var DataLost = errors.New("lost data")

// Read implements io.Reader's Read function.
// Given a byte slice, it will either copy a non-zero number of bytes into
// that slice and return the number of bytes and a nil error, or it will
// leave slice p as is and return 0, io.EOF.
func (r *TCPReaderStream) Read(p []byte) (int, error) {
	if !r.initiated {
		panic("TCPReaderStream not created via NewReaderStream")
	}
	var ok bool
	r.stripEmpty()
	for !r.closed && len(r.current) == 0 {
		if r.first {
			r.first = false
		} else {
			r.done <- true
		}
		if r.current, ok = <-r.reassembled; ok {
			r.stripEmpty()
		} else {
			r.closed = true
		}
	}
	if len(r.current) > 0 {
		current := &r.current[0]
		if r.LossErrors && !r.lossReported && current.Skip != 0 {
			r.lossReported = true
			return 0, DataLost
		}
		length := copy(p, current.Bytes)
		current.Bytes = current.Bytes[length:]
		return length, nil
	}
	return 0, io.EOF
}

// Seen returns the time the data returned by Read was seen on the wire.
// Returns io.EOF if no data was returned.
//
// Note: this is likely to be time for the data seen.  This is likely to
// not include time for initial connection.
// If you use something like a buffered reader, you are quite likely to
// see various data points dropped.  Perhaps wrap it up in something to
// capture those times first.
func (r *TCPReaderStream) Seen() (time.Time, error) {
	if len(r.current) > 0 {
		current := &r.current[0]
		return current.Seen, nil
	}
	return time.Time{}, io.EOF
}

// Close implements io.Closer's Close function, making TCPReaderStream a
// io.ReadCloser.  It discards all remaining bytes in the reassembly in a
// manner that's safe for the assembler (IE: it doesn't block).
func (r *TCPReaderStream) Close() error {
	r.current = nil
	r.closed = true
	for {
		if _, ok := <-r.reassembled; !ok {
			return nil
		}
		r.done <- true
	}
}
