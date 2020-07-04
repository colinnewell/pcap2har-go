package reader_test

import (
	"strings"
	"testing"

	"github.com/colinnewell/pcap2har-go/internal/reader"
	"github.com/google/go-cmp/cmp"
)

func TestSavePointReader(t *testing.T) {
	r := strings.NewReader("test this thing can do lots")

	sp := reader.NewSavePointReader(r)
	var buf [4]byte

	sp.Read(buf[:])

	if !cmp.Equal(buf[:], []byte("test")) {
		t.Errorf("Simple read failed")
	}

	sp.SavePoint()

	sp.Read(buf[:])

	if !cmp.Equal(buf[:], []byte(" thi")) {
		t.Errorf("Next read failed")
	}

	sp.Restore()

	sp.Read(buf[:])

	if !cmp.Equal(buf[:], []byte(" thi")) {
		t.Errorf("Repeated read failed")
	}

	sp.Reset()

	sp.Read(buf[:])

	if !cmp.Equal(buf[:], []byte("s th")) {
		t.Errorf("Next read failed")
	}

	sp.SavePoint()

	sp.Read(buf[:])

	if !cmp.Equal(buf[:], []byte("ing ")) {
		t.Errorf("Next read failed")
	}

	sp.Reset()
	sp.Read(buf[:])

	if !cmp.Equal(buf[:], []byte("can ")) {
		t.Errorf("Next read failed")
	}

	sp.Restore()
	sp.Read(buf[:])

	if !cmp.Equal(buf[:], []byte("do l")) {
		t.Errorf("Next read failed")
	}
}

// FIXME: should test uneven buffers.
