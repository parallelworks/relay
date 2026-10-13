// Package rawconnect sends CONNECT requests with caller-chosen header fields over HTTP/1.1 or
// HTTP/2, so tests can send requests a well-behaved client never would.
package rawconnect

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"time"
)

// MaxBody caps how much of a refusal's body is read.
const MaxBody = 64 << 10

// Request is one CONNECT request.
type Request struct {
	Addr      string
	Roots     *x509.CertPool
	Authority string
	Header    http.Header
	HTTP2     bool
}

// Response is the relay's answer. Body is empty for a 2xx.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       string
}

// Conn is an open tunnel.
type Conn interface {
	io.ReadWriteCloser
	CloseWrite() error
}

func (r *Request) tlsConfig(proto string) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: r.Roots, NextProtos: []string{proto}}
}

// Do sends r. On a 2xx response it also returns the tunnel.
func Do(ctx context.Context, r *Request) (*Response, Conn, error) {
	if r.HTTP2 {
		return doHTTP2(ctx, r)
	}
	return doHTTP1(ctx, r)
}

func refusal(resp *http.Response) (*Response, error) {
	b, err := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	return &Response{StatusCode: resp.StatusCode, Header: resp.Header, Body: string(b)}, errors.Join(err, resp.Body.Close())
}

func doHTTP1(ctx context.Context, r *Request) (*Response, Conn, error) {
	d := &tls.Dialer{Config: r.tlsConfig("http/1.1")}
	nc, err := d.DialContext(ctx, "tcp", r.Addr)
	if err != nil {
		return nil, nil, err
	}
	conn := nc.(*tls.Conn)
	if deadline, ok := ctx.Deadline(); ok {
		if derr := conn.SetDeadline(deadline); derr != nil {
			return nil, nil, errors.Join(derr, conn.Close())
		}
	}
	req := &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Host: r.Authority},
		Host:       r.Authority,
		Header:     r.Header,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	if werr := req.Write(conn); werr != nil {
		return nil, nil, errors.Join(werr, conn.Close())
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, nil, errors.Join(err, conn.Close())
	}
	if resp.StatusCode/100 != 2 {
		out, rerr := refusal(resp)
		return out, nil, errors.Join(rerr, conn.Close())
	}
	if derr := conn.SetDeadline(time.Time{}); derr != nil {
		return nil, nil, errors.Join(derr, conn.Close())
	}
	return &Response{StatusCode: resp.StatusCode, Header: resp.Header}, &h1Conn{Conn: conn, r: br}, nil
}

type h1Conn struct {
	*tls.Conn
	r *bufio.Reader
}

func (c *h1Conn) Read(b []byte) (int, error) { return c.r.Read(b) }

func doHTTP2(ctx context.Context, r *Request) (*Response, Conn, error) {
	protocols := new(http.Protocols)
	protocols.SetHTTP2(true)
	tr := &http.Transport{TLSClientConfig: r.tlsConfig("h2"), Protocols: protocols, ForceAttemptHTTP2: true}
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+r.Addr, pr)
	if err != nil {
		return nil, nil, err
	}
	req.Host = r.Authority
	req.Header = r.Header
	resp, err := tr.RoundTrip(req)
	if err != nil {
		tr.CloseIdleConnections()
		return nil, nil, errors.Join(err, pw.Close())
	}
	if resp.StatusCode/100 != 2 {
		out, rerr := refusal(resp)
		tr.CloseIdleConnections()
		return out, nil, errors.Join(rerr, pw.Close())
	}
	return &Response{StatusCode: resp.StatusCode, Header: resp.Header}, &h2Conn{body: resp.Body, pw: pw, tr: tr}, nil
}

type h2Conn struct {
	body io.ReadCloser
	pw   *io.PipeWriter
	tr   *http.Transport
}

func (c *h2Conn) Read(b []byte) (int, error)  { return c.body.Read(b) }
func (c *h2Conn) Write(b []byte) (int, error) { return c.pw.Write(b) }
func (c *h2Conn) CloseWrite() error           { return c.pw.Close() }

func (c *h2Conn) Close() error {
	err := errors.Join(c.pw.Close(), c.body.Close())
	c.tr.CloseIdleConnections()
	return err
}
