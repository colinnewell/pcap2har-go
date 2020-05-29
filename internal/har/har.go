package har

import (
	"time"

	"github.com/colinnewell/pcap2har-go/internal/reader"
)

type Creator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type Page struct {
	StartedDateTime time.Time `json:"startedDateTime"`
	ID              string    `json:"id"`
	Title           string    `json:"title"`
	PageTimings     struct {
		OnContentLoad float64     `json:"onContentLoad"`
		OnLoad        interface{} `json:"onLoad"`
	} `json:"pageTimings"`
}

type Header KeyValues

type Cookie struct {
	Name     string    `json:"name"`
	Value    string    `json:"value"`
	Expires  time.Time `json:"expires"`
	HTTPOnly bool      `json:"httpOnly"`
	Secure   bool      `json:"secure"`
}

type RequestInfo struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	HTTPVersion string      `json:"httpVersion"`
	Headers     []Header    `json:"headers"`
	QueryString []KeyValues `json:"queryString"`
	Cookies     []Cookie    `json:"cookies"`
	HeadersSize int         `json:"headersSize"`
	BodySize    int         `json:"bodySize"`
	Content     ContentInfo `json:"content"`
}

type ContentInfo struct {
	MimeType string `json:"mimeType"`
	Size     int    `json:"size"`
	Text     string `json:"text"`
}

type KeyValues struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type ResponseInfo struct {
	Status       int           `json:"status"`
	StatusText   string        `json:"statusText"`
	HTTPVersion  string        `json:"httpVersion"`
	Headers      []Header      `json:"headers"`
	Cookies      []interface{} `json:"cookies"`
	Content      ContentInfo   `json:"content"`
	RedirectURL  string        `json:"redirectURL"`
	HeadersSize  int           `json:"headersSize"`
	BodySize     int           `json:"bodySize"`
	TransferSize int           `json:"_transferSize"`
}

type Entry struct {
	StartedDateTime time.Time    `json:"startedDateTime"`
	Time            float64      `json:"time"`
	Request         RequestInfo  `json:"request"`
	Response        ResponseInfo `json:"response"`
	ServerIPAddress string       `json:"serverIPAddress"`
	Connection      string       `json:"connection,omitempty"`
}

type Har struct {
	Log struct {
		Version string  `json:"version"`
		Creator Creator `json:"creator"`
		Pages   []Page  `json:"pages"`
		Entries []Entry `json:"entries"`
	} `json:"log"`
}

func (h *Har) AddEntry(v reader.Conversation) {
	var reqheaders []Header
	for k, values := range v.Request.Header {
		for _, v := range values {
			reqheaders = append(reqheaders, Header{Name: k, Value: v})
		}
	}
	if v.Request.Host != "" {
		reqheaders = append(reqheaders, Header{
			Name: "Host", Value: v.Request.Host,
		})
	}
	cookies := v.Request.Cookies()
	cookieInfo := make([]Cookie, len(cookies))
	for i, c := range cookies {
		cookieInfo[i] = Cookie{
			Name:     c.Name,
			Value:    c.Value,
			Expires:  c.Expires,
			HTTPOnly: c.HttpOnly,
			Secure:   c.Secure,
		}
	}
	var queryString []KeyValues
	for k, values := range v.Request.URL.Query() {
		for _, v := range values {
			queryString = append(queryString, KeyValues{Name: k, Value: v})
		}
	}
	var mimeType string
	mimeTypes, ok := v.Request.Header["Content-Type"]
	if ok {
		mimeType = mimeTypes[0]
	}
	// for some reason host isn't hooked up
	v.Request.URL.Host = v.Request.Host
	if v.Request.TLS == nil {
		v.Request.URL.Scheme = "http"
	} else {
		v.Request.URL.Scheme = "https"
	}
	req := RequestInfo{
		Cookies:     cookieInfo,
		Headers:     reqheaders,
		Method:      v.Request.Method,
		URL:         v.Request.URL.String(),
		QueryString: queryString,
		Content: ContentInfo{
			Size:     len(v.RequestBody),
			MimeType: mimeType,
			Text:     string(v.RequestBody),
		},
	}
	resp := ResponseInfo{}
	if v.Response != nil {
		mimeTypes, ok = v.Response.Header["Content-Type"]
		if ok {
			mimeType = mimeTypes[0]
		}
		var headers []Header
		for k, values := range v.Response.Header {
			for _, v := range values {
				headers = append(headers, Header{Name: k, Value: v})
			}
		}
		resp = ResponseInfo{
			Content: ContentInfo{
				Size:     len(v.ResponseBody),
				MimeType: mimeType,
				Text:     string(v.ResponseBody),
			},
			Headers:     headers,
			HTTPVersion: v.Response.Proto,
			StatusText:  v.Response.Status,
			Status:      v.Response.StatusCode,
		}
	}
	entry := Entry{
		Request:  req,
		Response: resp,
	}
	h.Log.Entries = append(h.Log.Entries, entry)
}
