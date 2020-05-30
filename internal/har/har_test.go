package har_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/colinnewell/pcap2har-go/internal/har"
	"github.com/colinnewell/pcap2har-go/internal/reader"
	"github.com/google/go-cmp/cmp"
	"github.com/google/gopacket"
)

func TestEmptyHarOutput(t *testing.T) {
	var h har.Har

	bytes, err := json.Marshal(h)
	if err != nil {
		t.Error(err)
	}

	if diff := cmp.Diff(string(bytes),
		`{"log":{"version":"","creator":{"name":"","version":""},"pages":null,"entries":null}}`,
	); diff != "" {
		t.Errorf("Different json (-got +expected):\n%s\n", diff)
	}
}

func TestHarRequestOnly(t *testing.T) {
	var h har.Har

	h.Log.Version = "1.2"
	h.Log.Creator.Name = "pcap2har"
	h.Log.Creator.Version = "test"

	url, err := url.Parse("http://localhost:3000/test.html?q=3&v=4")
	host := url.Host
	// replicate situation we find when we construct Requests by reading.
	url.Host = ""
	if err != nil {
		t.Error(err)
	}
	fmt.Printf("%#v", url)

	r := reader.Conversation{
		Address: reader.ConversationAddress{IP: gopacket.NewFlow(1,
			[]byte{0x7f, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0}, []byte{0x7f, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}), Port: gopacket.NewFlow(4,
			[]byte{0x23, 0x36, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0}, []byte{0xa8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,
				0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0})},
		Request: &http.Request{
			Method:     "GET",
			URL:        url,
			Host:       host,
			Proto:      "HTTP/1.0",
			ProtoMajor: 1,
			ProtoMinor: 0,
			Header:     http.Header{},
		},
	}
	h.AddEntry(r)

	bytes, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		t.Error(err)
	}

	expected := strings.Join([]string{
		"{",
		`  "log": {`,
		`    "version": "1.2",`,
		`    "creator": {`,
		`      "name": "pcap2har",`,
		`      "version": "test"`,
		"    },",
		`    "pages": [`,
		"      {",
		`        "startedDateTime": "0001-01-01T00:00:00Z",`,
		`        "id": "page_1",`,
		`        "title": "http://localhost:3000/test.html?q=3\u0026v=4",`,
		`        "pageTimings": {`,
		`          "onContentLoad": 0,`,
		`          "onLoad": 0`,
		"        }",
		"      }",
		"    ],",
		`    "entries": [`,
		"      {",
		`        "startedDateTime": "0001-01-01T00:00:00Z",`,
		`        "time": 0,`,
		`        "request": {`,
		`          "method": "GET",`,
		`          "url": "http://localhost:3000/test.html?q=3\u0026v=4",`,
		`          "httpVersion": "",`,
		`          "headers": [`,
		"            {",
		`              "name": "Host",`,
		`              "value": "localhost:3000"`,
		"            }",
		"          ],",
		`          "queryString": [`,
		"            {",
		`              "name": "q",`,
		`              "value": "3"`,
		"            },",
		"            {",
		`              "name": "v",`,
		`              "value": "4"`,
		"            }",
		"          ],",
		`          "cookies": [],`,
		`          "headersSize": 0,`,
		`          "bodySize": 0,`,
		`          "content": {`,
		`            "mimeType": "",`,
		`            "size": 0,`,
		`            "text": ""`,
		"          }",
		"        },",
		`        "response": {`,
		`          "status": 0,`,
		`          "statusText": "",`,
		`          "httpVersion": "",`,
		`          "headers": null,`,
		`          "cookies": null,`,
		`          "content": {`,
		`            "mimeType": "",`,
		`            "size": 0,`,
		`            "text": ""`,
		"          },",
		`          "redirectURL": "",`,
		`          "headersSize": 0,`,
		`          "bodySize": 0,`,
		`          "_transferSize": 0`,
		"        },",
		`        "serverIPAddress": ""`,
		"      }",
		"    ]",
		"  }",
		"}",
	}, "\n")
	if diff := cmp.Diff(string(bytes), expected); diff != "" {
		t.Errorf("Different json (-got +expected):\n%s\n", diff)
	}
}

// FIXME: test round trip of the JSON
