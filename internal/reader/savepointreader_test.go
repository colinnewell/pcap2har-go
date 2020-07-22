package reader_test

import (
	"io/ioutil"
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

	sp.Restore(false)

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

	sp.Restore(false)
	rest, err := ioutil.ReadAll(sp)
	if err != nil {
		t.Error(err)
	}

	if diff := cmp.Diff(rest, []byte("do lots")); diff != "" {
		t.Errorf("Final read after restore\n%s", diff)
	}

	sp.Restore(false)
	sp.Read(buf[:])

	if !cmp.Equal(buf[:], []byte("do l")) {
		t.Errorf("Next read failed")
	}

	rest, err = ioutil.ReadAll(sp)
	if err != nil {
		t.Error(err)
	}

	if !cmp.Equal(rest, []byte("ots")) {
		t.Errorf("Next read failed")
	}

	sp.Restore(true)
	rest, err = ioutil.ReadAll(sp)
	if err != nil {
		t.Error(err)
	}

	if diff := cmp.Diff(rest, []byte("do lots")); diff != "" {
		t.Errorf("Final read after restore\n%s", diff)
	}
}

// FIXME: should test uneven buffers.
