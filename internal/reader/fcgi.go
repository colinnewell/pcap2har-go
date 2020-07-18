package reader

import (
	"encoding/binary"
	"errors"
	"io"

	"github.com/google/gopacket"
)

// code copied from src/net/http/fcgi/fcgi.go
const (
	maxWrite = 65535 // maximum record body
	maxPad   = 255
)

type recType uint8

const (
	typeBeginRequest    recType = 1
	typeAbortRequest    recType = 2
	typeEndRequest      recType = 3
	typeParams          recType = 4
	typeStdin           recType = 5
	typeStdout          recType = 6
	typeStderr          recType = 7
	typeData            recType = 8
	typeGetValues       recType = 9
	typeGetValuesResult recType = 10
	typeUnknownType     recType = 11
)

const (
	roleResponder = iota + 1 // only Responders are implemented.
	roleAuthorizer
	roleFilter
)

const (
	statusRequestComplete = iota
	statusCantMultiplex
	statusOverloaded
	statusUnknownRole
)

type header struct {
	Version       uint8
	Type          recType
	ID            uint16
	ContentLength uint16
	PaddingLength uint8
	Reserved      uint8
}

type beginRequest struct {
	role     uint16
	flags    uint8
	reserved [5]uint8
}

type record struct {
	h   header
	buf [maxWrite + maxPad]byte
}

func (rec *record) read(r io.Reader) (err error) {
	if err = binary.Read(r, binary.BigEndian, &rec.h); err != nil {
		return err
	}
	if rec.h.Version != 1 {
		return errors.New("fcgi: invalid header version")
	}
	n := int(rec.h.ContentLength) + int(rec.h.PaddingLength)
	if _, err = io.ReadFull(r, rec.buf[:n]); err != nil {
		return err
	}
	return nil
}

func (r *record) content() []byte {
	return r.buf[:r.h.ContentLength]
}

func (c *child) handleRecord(rec *record) error {
	c.mu.Lock()
	req, ok := c.requests[rec.h.Id]
	c.mu.Unlock()
	if !ok && rec.h.Type != typeBeginRequest && rec.h.Type != typeGetValues {
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
			c.conn.writeEndRequest(rec.h.Id, 0, statusUnknownRole)
			return nil
		}
		req = newRequest(rec.h.Id, br.flags)
		c.mu.Lock()
		c.requests[rec.h.Id] = req
		c.mu.Unlock()
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
			go c.serveRequest(req, body)
		}
		if len(content) > 0 {
			// TODO(eds): This blocks until the handler reads from the pipe.
			// If the handler takes a long time, it might be a problem.
			req.pw.Write(content)
		} else if req.pw != nil {
			req.pw.Close()
		}
		return nil
	case typeGetValues:
		values := map[string]string{"FCGI_MPXS_CONNS": "1"}
		c.conn.writePairs(typeGetValuesResult, 0, values)
		return nil
	case typeData:
		// If the filter role is implemented, read the data stream here.
		return nil
	case typeAbortRequest:
		c.mu.Lock()
		delete(c.requests, rec.h.Id)
		c.mu.Unlock()
		c.conn.writeEndRequest(rec.h.Id, 0, statusRequestComplete)
		if req.pw != nil {
			req.pw.CloseWithError(ErrRequestAborted)
		}
		if !req.keepConn {
			// connection will close upon return
			return errCloseConn
		}
		return nil
	default:
		b := make([]byte, 8)
		b[0] = byte(rec.h.Type)
		c.conn.writeRecord(typeUnknownType, 0, b)
		return nil
	}
}
func (c *child) serve() {
	defer c.conn.Close()
	defer c.cleanUp()
	var rec record
	for {
		if err := rec.read(c.conn.rwc); err != nil {
			return
		}
		if err := c.handleRecord(&rec); err != nil {
			return
		}
	}
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

func (h *HTTPConversationReaders) ReadFCGIRequest(spr *SavePointReader, t *TimeCaptureReader, a, b gopacket.Flow) error {
	// try to product an HTTP request from the stream
	h.addRequest(a, b, req, body, t.Seen())
	return nil
}
