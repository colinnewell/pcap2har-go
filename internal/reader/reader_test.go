package reader_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/colinnewell/pcap2har-go/internal/reader"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/gopacket"
)

func TestHTTPStreamRead(t *testing.T) {
	req := "GET / HTTP/1.0\r\n\r\n"
	response := strings.Join([]string{"HTTP/1.1 200 OK",
		"Access-Control-Allow-Origin: *",
		"Content-Type: application/json; charset=utf-8",
		"Content-Length: 2",
		"Date: Tue, 19 May 2020 15:10:48 GMT",
		"Connection: keep-alive",
		"",
		"{}"},
		"\r\n")
	ipFlow := gopacket.NewFlow(1, []byte{0x7f, 0x0, 0x0, 0x1}, []byte{0x7f,
		0x0, 0x0, 0x1})
	portFlow := gopacket.NewFlow(4, []byte{0x23, 0x36}, []byte{0xa8, 0x0})

	r := reader.New()
	r.ReadRequest(strings.NewReader(req), ipFlow, portFlow)
	r.ReadRequest(strings.NewReader(response), ipFlow.Reverse(), portFlow.Reverse())

	expected := []reader.Conversation{reader.Conversation{
		Address: reader.ConversationAddress{IP: ipFlow, Port: portFlow},
		Request: &http.Request{
			Method:     "GET",
			URL:        &url.URL{Path: "/"},
			Proto:      "HTTP/1.0",
			ProtoMajor: 1,
			ProtoMinor: 0,
			Header:     http.Header{},
			Close:      true,
			Body:       http.NoBody,
			RequestURI: "/",
		},
		Response: &http.Response{
			Status:     "200 OK",
			StatusCode: 200,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Header: http.Header{
				"Access-Control-Allow-Origin": {"*"},
				"Connection":                  {"keep-alive"},
				"Content-Length":              {"2"},
				"Content-Type":                {"application/json; charset=utf-8"},
				"Date":                        {"Tue, 19 May 2020 15:10:48 GMT"},
			},
			ContentLength: 2,
		},
		RequestBody:  []byte(""),
		ResponseBody: []byte("{}"),
	}}

	if diff := cmp.Diff(r.GetConversations(), expected,
		cmp.Comparer(requestCompare),
		cmp.Comparer(flowCompare),
		cmpopts.IgnoreFields(http.Response{}, "Body"),
	); diff != "" {
		t.Errorf("Conversations don't match (-got +expected):\n%s\n", diff)
	}
}

func requestCompare(x, y http.Request) bool {
	// FIXME: need to compare Header too
	return x.Method == y.Method &&
		*x.URL == *y.URL &&
		x.Host == y.Host &&
		x.Proto == y.Proto &&
		x.ProtoMinor == y.ProtoMinor &&
		x.ProtoMajor == y.ProtoMajor
}

func flowCompare(x, y gopacket.Flow) bool {
	return x.String() == y.String()
}
