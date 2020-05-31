package har_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
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

	r := reader.Conversation{
		Address: reader.ConversationAddress{IP: gopacket.NewFlow(1,
			[]byte{0x7f, 0x0, 0x0, 0x1}, []byte{0x7f, 0x0, 0x0, 0x1}), Port: gopacket.NewFlow(4,
			[]byte{0x23, 0x36}, []byte{0xa8, 0x0})},
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

	// sort the query string list to make the test results consistent
	params := h.Log.Entries[0].Request.QueryString
	sort.Slice(params, func(i, j int) bool {
		return params[i].Name < params[j].Name
	})

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
		`        "serverIPAddress": "127.0.0.1"`,
		"      }",
		"    ]",
		"  }",
		"}",
	}, "\n")
	if diff := cmp.Diff(string(bytes), expected); diff != "" {
		t.Errorf("Different json (-got +expected):\n%s\n", diff)
	}
}

func TestHarFullConversation(t *testing.T) {
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

	r := reader.Conversation{
		Address: reader.ConversationAddress{IP: gopacket.NewFlow(1,
			[]byte{0x7f, 0x0, 0x0, 0x1}, []byte{0x7f, 0x0, 0x0, 0x1}), Port: gopacket.NewFlow(4,
			[]byte{0x23, 0x36}, []byte{0xa8, 0x0})},
		Request: &http.Request{
			Method:     "GET",
			URL:        url,
			Host:       host,
			Proto:      "HTTP/1.0",
			ProtoMajor: 1,
			ProtoMinor: 0,
			Header:     http.Header{},
		},
		RequestBody: []byte("request body"),
		Response: &http.Response{
			Status:           "200 OK",
			StatusCode:       200,
			Proto:            "HTTP/1.0",
			ProtoMajor:       1,
			ProtoMinor:       0,
			Header:           http.Header{},
			ContentLength:    13,
			TransferEncoding: []string{"base64"},
		},
		ResponseBody: []byte("response body"),
	}
	h.AddEntry(r)

	params := h.Log.Entries[0].Request.QueryString
	sort.Slice(params, func(i, j int) bool {
		return params[i].Name < params[j].Name
	})

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
		`            "size": 12,`,
		`            "text": "request body"`,
		"          }",
		"        },",
		`        "response": {`,
		`          "status": 200,`,
		`          "statusText": "200 OK",`,
		`          "httpVersion": "HTTP/1.0",`,
		`          "headers": null,`,
		`          "cookies": null,`,
		`          "content": {`,
		`            "mimeType": "",`,
		`            "size": 13,`,
		`            "text": "response body"`,
		"          },",
		`          "redirectURL": "",`,
		`          "headersSize": 0,`,
		`          "bodySize": 0,`,
		`          "_transferSize": 0`,
		"        },",
		`        "serverIPAddress": "127.0.0.1"`,
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
