// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// this is modified from the core Go source code.

package fcgi

// This file implements FastCGI from the perspective of a Child process.

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cgi"
	"regexp"
	"strings"
	"sync"
)

// request holds the state for an in-progress request. As soon as it's complete,
// it's converted to an http.Request.
type request struct {
	pw        *io.PipeWriter
	reqId     uint16
	params    map[string]string
	buf       [1024]byte
	rawParams []byte
	keepConn  bool
}

// envVarsContextKey uniquely identifies a mapping of CGI
// environment variables to their values in a request context
type envVarsContextKey struct{}

var httpStatus = regexp.MustCompile(`(?m)^Status:\s*(.*)\s*$`)

func newRequest(reqId uint16, flags uint8) *request {
	r := &request{
		reqId:    reqId,
		params:   map[string]string{},
		keepConn: flags&flagKeepConn != 0,
	}
	r.rawParams = r.buf[:0]
	return r
}

// parseParams reads an encoded []byte into Params.
func (r *request) parseParams() {
	text := r.rawParams
	r.rawParams = nil
	for len(text) > 0 {
		keyLen, n := readSize(text)
		if n == 0 {
			return
		}
		text = text[n:]
		valLen, n := readSize(text)
		if n == 0 {
			return
		}
		text = text[n:]
		if int(keyLen)+int(valLen) > len(text) {
			return
		}
		key := readString(text, keyLen)
		text = text[keyLen:]
		val := readString(text, valLen)
		text = text[valLen:]
		r.params[key] = val
	}
}

type Child struct {
	// FIXME: should I add the sync.Mutex back in to protect the map?
	requests         map[uint16]*request // keyed by request ID
	requestCallback  func(*http.Request)
	responseCallback func(*http.Response, []byte)
	wg               sync.WaitGroup
}

func NewChild(processRequest func(*http.Request), processResponse func(*http.Response, []byte)) *Child {
	return &Child{
		requests:         make(map[uint16]*request),
		requestCallback:  processRequest,
		responseCallback: processResponse,
	}
}

func (c *Child) ReadRequest(rdr io.Reader) error {
	var rec record
	defer func() {
		// FIXME: figure out what order I should be implemneting these in
		c.wg.Wait()
		c.cleanUp()
	}()
	for {
		if err := rec.read(rdr); err != nil {
			return err
		}
		if err := c.handleRecord(&rec); err != nil {
			return err
		}
	}
}

func (c *Child) cleanUp() {
	for _, req := range c.requests {
		if req.pw != nil {
			// race with call to Close in c.serveRequest doesn't matter because
			// Pipe(Reader|Writer).Close are idempotent
			err := req.pw.CloseWithError(ErrConnClosed)
			if err != nil {
				log.Println("cleanUp(): ", err)
			}
		}
	}
}

var emptyBody = ioutil.NopCloser(strings.NewReader(""))

// ErrConnClosed is returned by Read when a handler attempts to read the body of
// a request after the connection to the web server has been closed.
var ErrConnClosed = errors.New("fcgi: connection to web server closed")

func (c *Child) handleRecord(rec *record) error {
	req, ok := c.requests[rec.h.Id]
	// FIXME: need to detect when we don't have a request I guess
	if !ok &&
		rec.h.Type != typeBeginRequest &&
		rec.h.Type != typeStdout &&
		rec.h.Type != typeStderr &&
		rec.h.Type != typeGetValues {
		// The spec says to ignore unknown request IDs.
		return nil
	}

	switch rec.h.Type {
	case typeBeginRequest:
		if req != nil {
			// The server is trying to begin a request with the same ID
			// as an in-progress request. This is an error.
			return errors.New("fcgi: received ID that is already in-flight")
		}

		var br beginRequest
		if err := br.read(rec.content()); err != nil {
			return err
		}
		if br.role != roleResponder {
			// FIXME: we don't know how to deal with this. perhaps return an error?
			// or just drop the traffic?
			return nil
		}
		req = newRequest(rec.h.Id, br.flags)
		c.requests[rec.h.Id] = req
		return nil
	case typeParams:
		// NOTE(eds): Technically a key-value pair can straddle the boundary
		// between two packets. We buffer until we've received all parameters.
		if len(rec.content()) > 0 {
			req.rawParams = append(req.rawParams, rec.content()...)
			return nil
		}
		req.parseParams()
		return nil
	// FIXME: also add in the things for responses
	case typeStderr:
		//content := rec.content()
		//fmt.Printf("Errors:\n%s", content)
		return nil
	case typeStdout:
		if req, ok = c.requests[rec.h.Id]; !ok {
			req = newRequest(rec.h.Id, 0)
			c.requests[rec.h.Id] = req
		}
		content := rec.content()
		if req.pw == nil {
			var body io.ReadCloser
			if len(content) > 0 {
				// body could be an io.LimitReader, but it shouldn't matter
				// as long as both sides are behaving.
				body, req.pw = io.Pipe()
			} else {
				body = emptyBody
			}
			c.wg.Add(1)
			go c.serveResponse(req, body)
		}
		if len(content) > 0 {
			if !ok {
				// assume this is the first block, check if there is a status
				// header indicating this isn't a standard 200 OK.
				matches := httpStatus.FindSubmatch(content)
				status := "200 OK"
				if len(matches) > 0 {
					status = string(matches[1])
				}
				_, err := req.pw.Write([]byte(fmt.Sprintf("HTTP/1.0 %s\r\n", status)))
				if err != nil {
					return err
				}
			}
			_, err := req.pw.Write(content)
			if err != nil {
				return err
			}
		} else if req.pw != nil {
			err := req.pw.Close()
			if err != nil {
				return err
			}
		}
		return nil
	case typeStdin:
		content := rec.content()
		if req.pw == nil {
			var body io.ReadCloser
			if len(content) > 0 {
				// body could be an io.LimitReader, but it shouldn't matter
				// as long as both sides are behaving.
				body, req.pw = io.Pipe()
			} else {
				body = emptyBody
			}
			c.wg.Add(1)
			go c.serveRequest(req, body)
		}
		if len(content) > 0 {
			// TODO(eds): This blocks until the handler reads from the pipe.
			// If the handler takes a long time, it might be a problem.
			_, err := req.pw.Write(content)
			if err != nil {
				return err
			}
		} else if req.pw != nil {
			err := req.pw.Close()
			if err != nil {
				return err
			}
		}
		return nil
	case typeGetValues:
		// probably don't do anything here.  looks like something supposed to
		// illicit a response from the server which we might be interested in,
		// but not the fact that it was requested.
		return nil
	case typeEndRequest:
		if req.pw != nil {
			req.pw.Close()
		}
		delete(c.requests, rec.h.Id)
		return nil
	case typeData:
		// If the filter role is implemented, read the data stream here.
		// FIXME:
		return nil
	case typeAbortRequest:
		// perhaps add that to the HAR?
		delete(c.requests, rec.h.Id)
		return nil
	default:
		// FIXME: perhaps log for now?
		return nil
	}
}

func (c *Child) serveResponse(req *request, body io.ReadCloser) {
	// FIXME: it would be nice to pass more meta data through the request too
	defer c.wg.Done()
	buf := bufio.NewReader(body)
	res, err := http.ReadResponse(buf, nil)
	if err != nil {
		return
	}
	defer res.Body.Close()
	// FIXME: consider a savepoint reader to have another crack at the body?
	respBody, _ := ioutil.ReadAll(res.Body)
	c.responseCallback(res, respBody)
}

func (c *Child) serveRequest(req *request, body io.ReadCloser) {
	defer c.wg.Done()
	httpReq, err := cgi.RequestFromMap(req.params)
	if err != nil {
		return
	}
	httpReq.Body = body
	withoutUsedEnvVars := filterOutUsedEnvVars(req.params)
	envVarCtx := context.WithValue(httpReq.Context(), envVarsContextKey{}, withoutUsedEnvVars)
	httpReq = httpReq.WithContext(envVarCtx)
	c.requestCallback(httpReq)
}

// filterOutUsedEnvVars returns a new map of env vars without the
// variables in the given envVars map that are read for creating each http.Request
func filterOutUsedEnvVars(envVars map[string]string) map[string]string {
	withoutUsedEnvVars := make(map[string]string)
	for k, v := range envVars {
		if addFastCGIEnvToContext(k) {
			withoutUsedEnvVars[k] = v
		}
	}
	return withoutUsedEnvVars
}

// ProcessEnv returns FastCGI environment variables associated with the request r
// for which no effort was made to be included in the request itself - the data
// is hidden in the request's context. As an example, if REMOTE_USER is set for a
// request, it will not be found anywhere in r, but it will be included in
// ProcessEnv's response (via r's context).
func ProcessEnv(r *http.Request) map[string]string {
	env, _ := r.Context().Value(envVarsContextKey{}).(map[string]string)
	return env
}

// addFastCGIEnvToContext reports whether to include the FastCGI environment variable s
// in the http.Request.Context, accessible via ProcessEnv.
func addFastCGIEnvToContext(s string) bool {
	// Exclude things supported by net/http natively:
	switch s {
	case "CONTENT_LENGTH", "CONTENT_TYPE", "HTTPS",
		"PATH_INFO", "QUERY_STRING", "REMOTE_ADDR",
		"REMOTE_HOST", "REMOTE_PORT", "REQUEST_METHOD",
		"REQUEST_URI", "SCRIPT_NAME", "SERVER_PROTOCOL":
		return false
	}
	if strings.HasPrefix(s, "HTTP_") {
		return false
	}
	// Explicitly include FastCGI-specific things.
	// This list is redundant with the default "return true" below.
	// Consider this documentation of the sorts of things we expect
	// to maybe see.
	switch s {
	case "REMOTE_USER":
		return true
	}
	// Unknown, so include it to be safe.
	return true
}
