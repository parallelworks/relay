package server

import (
	"bytes"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/parallelworks/relay/tunnel"
)

// errStreamEnded ends an HTTP/2 tunnel when the target finishes sending. net/http ends a response
// stream only when the handler returns, so the relay cannot half-close an HTTP/2 tunnel.
var errStreamEnded = errors.New("server: target ended the stream")

const established = "HTTP/1.1 200 OK\r\n\r\n"

func accept(w http.ResponseWriter, r *http.Request) (tunnel.Conn, error) {
	rc := http.NewResponseController(w)
	if r.ProtoMajor == 1 {
		return acceptHTTP1(rc)
	}
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return nil, err
	}
	return &h2Conn{body: r.Body, w: w, rc: rc}, nil
}

func acceptHTTP1(rc *http.ResponseController) (tunnel.Conn, error) {
	nc, brw, err := rc.Hijack()
	if err != nil {
		return nil, err
	}
	conn, ok := nc.(*tls.Conn)
	if !ok {
		return nil, errors.Join(fmt.Errorf("server: hijacked %T, want *tls.Conn", nc), nc.Close())
	}
	if derr := conn.SetDeadline(time.Time{}); derr != nil {
		return nil, errors.Join(derr, conn.Close())
	}
	if _, werr := io.WriteString(conn, established); werr != nil {
		return nil, errors.Join(werr, conn.Close())
	}
	pending, err := brw.Peek(brw.Reader.Buffered())
	if err != nil {
		return nil, errors.Join(err, conn.Close())
	}
	return &h1Conn{Conn: conn, pending: bytes.Clone(pending)}, nil
}

// h1Conn reads the bytes net/http buffered past the request head, then the TLS connection itself:
// the hijacked bufio.Reader still enforces the request head's read limit.
type h1Conn struct {
	*tls.Conn
	pending []byte
}

func (c *h1Conn) Read(b []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(b, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

type h2Conn struct {
	body  io.ReadCloser
	w     http.ResponseWriter
	rc    *http.ResponseController
	ended atomic.Bool
}

func (c *h2Conn) Read(b []byte) (int, error) { return c.body.Read(b) }

func (c *h2Conn) Write(b []byte) (int, error) {
	n, err := c.w.Write(b)
	if err != nil {
		return n, err
	}
	return n, c.rc.Flush()
}

func (c *h2Conn) CloseWrite() error {
	c.ended.Store(true)
	return errStreamEnded
}

func (c *h2Conn) Close() error {
	err := c.body.Close()
	if !c.ended.Load() {
		err = errors.Join(err, c.rc.SetWriteDeadline(time.Now()))
	}
	return err
}
