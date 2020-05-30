package har_test

import (
	"encoding/json"
	"testing"

	"github.com/colinnewell/pcap2har-go/internal/har"
	"github.com/google/go-cmp/cmp"
)

func TestHarOutput(t *testing.T) {
	var h har.Har

	bytes, err := json.Marshal(h)
	if err != nil {
		t.Error(err)
	}
	if diff := cmp.Diff(string(bytes),
		`{"log":{"version":"","creator":{"name":"","version":""},"pages":null,"entries":null}}`,
	); diff != "" {
		t.Errorf("Different json (-wrote +read):\n%s\n", diff)
	}
}

// FIXME: test round trip of the JSON
