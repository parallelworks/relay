// Package client opens tunnels through a relay: an HTTP CONNECT request carrying a DPoP-bound
// access token, as SPEC.md describes. It depends only on the standard library and package dpop.
package client

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/parallelworks/relay/dpop"
)

// MaxErrorBody caps how much of a refusal's body is read.
const MaxErrorBody = 64 << 10

// ErrTarget reports a target that is not an IP literal and port.
var ErrTarget = errors.New("client: target must be an IP literal and port")

// Error is a relay's refusal of a tunnel request (SPEC.md, Errors).
type Error struct {
	StatusCode int
	// Title is the Problem Details title (RFC 9457).
	Title string
	// AuthError is the error code of the DPoP challenge (RFC 9449 §7.1), if any.
	AuthError string
	// RetryAfter is the Retry-After delay (RFC 9110 §10.2.3), if any.
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("relay refused the tunnel: %d %s", e.StatusCode, e.Title)
	if e.AuthError != "" {
		msg += " (" + e.AuthError + ")"
	}
	return msg
}

// Conn is an open tunnel. CloseWrite ends the client's stream while the target's bytes keep arriving.
type Conn interface {
	net.Conn
	CloseWrite() error
}

// Dialer opens tunnels. The zero value sends CONNECT over HTTP/1.1 and verifies the relay against
// the system roots.
type Dialer struct {
	// TLSConfig configures the connection to the relay. TLS 1.3 is required whatever it says.
	TLSConfig *tls.Config
	// HTTP2 sends CONNECT over HTTP/2 (RFC 9113 §8.5). Tunnels to one relay then share a connection,
	// and the returned Conn does not support deadlines.
	HTTP2 bool
	// NetDialer dials the relay. Nil uses a net.Dialer with TCP keepalive.
	NetDialer *net.Dialer

	once      sync.Once
	transport *http.Transport
	nonces    sync.Map
}

var defaultDialer Dialer

// Dial opens a tunnel to target through the relay at relayURL with the default Dialer.
func Dial(ctx context.Context, relayURL, target, token string, key crypto.Signer) (Conn, error) {
	return defaultDialer.Dial(ctx, relayURL, target, token, key)
}

// Dial opens a tunnel to target, an IP literal and port, through the relay at relayURL, an https
// URL with no path. token is the access token for the tunnel and key the private key it is bound
// to. ctx bounds only the opening of the tunnel.
func (d *Dialer) Dial(ctx context.Context, relayURL, target, token string, key crypto.Signer) (Conn, error) {
	addr, host, err := parseRelay(relayURL)
	if err != nil {
		return nil, err
	}
	ap, err := netip.ParseAddrPort(target)
	if err != nil || ap.Addr().Zone() != "" || ap.Port() == 0 {
		return nil, fmt.Errorf("%w: %q", ErrTarget, target)
	}
	prover, err := dpop.NewProver(key)
	if err != nil {
		return nil, err
	}
	authority := ap.String()
	nonce, _ := d.nonces.Load(addr)
	for attempt := 0; ; attempt++ {
		n, _ := nonce.(string)
		proof, err := prover.Proof(http.MethodConnect, dpop.TargetURI(authority), token, n)
		if err != nil {
			return nil, err
		}
		h := http.Header{}
		h.Set("Authorization", dpop.Scheme+" "+token)
		h.Set(dpop.HeaderName, proof)
		r := &request{addr: addr, host: host, authority: authority, header: h, target: net.TCPAddrFromAddrPort(ap)}
		conn, resp, err := d.do(ctx, r)
		if err != nil {
			return nil, err
		}
		if next := resp.Header.Get(dpop.NonceHeaderName); next != "" {
			d.nonces.Store(addr, next)
			nonce = next
		}
		if conn != nil {
			return conn, nil
		}
		refusal := refused(resp)
		if refusal.AuthError != "use_dpop_nonce" || attempt > 0 || resp.Header.Get(dpop.NonceHeaderName) == "" {
			return nil, refusal
		}
	}
}

func parseRelay(relayURL string) (addr, host string, err error) {
	u, err := url.Parse(relayURL)
	if err != nil {
		return "", "", fmt.Errorf("client: relay URL: %w", err)
	}
	if u.Scheme != "https" || u.Host == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", "", fmt.Errorf("client: relay URL %q must be https://host[:port]", relayURL)
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(u.Hostname(), port), u.Hostname(), nil
}

type request struct {
	addr      string
	host      string
	authority string
	header    http.Header
	target    net.Addr
}

type response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

func (d *Dialer) tlsConfig(host, proto string) *tls.Config {
	cfg := &tls.Config{}
	if d.TLSConfig != nil {
		cfg = d.TLSConfig.Clone()
	}
	cfg.MinVersion = tls.VersionTLS13
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	cfg.NextProtos = []string{proto}
	return cfg
}

func (d *Dialer) netDialer() *net.Dialer {
	if d.NetDialer != nil {
		return d.NetDialer
	}
	return &net.Dialer{KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second, Interval: 15 * time.Second, Count: 4}}
}

func (d *Dialer) do(ctx context.Context, r *request) (Conn, *response, error) {
	if d.HTTP2 {
		return d.doHTTP2(ctx, r)
	}
	return d.doHTTP1(ctx, r)
}

func (d *Dialer) doHTTP1(ctx context.Context, r *request) (Conn, *response, error) {
	td := &tls.Dialer{NetDialer: d.netDialer(), Config: d.tlsConfig(r.host, "http/1.1")}
	nc, err := td.DialContext(ctx, "tcp", r.addr)
	if err != nil {
		return nil, nil, err
	}
	tc := nc.(*tls.Conn)
	conn, resp, err := exchangeHTTP1(ctx, tc, r)
	if err != nil {
		return nil, nil, errors.Join(err, tc.Close())
	}
	if conn == nil {
		return nil, resp, tc.Close()
	}
	return conn, resp, nil
}

func exchangeHTTP1(ctx context.Context, tc *tls.Conn, r *request) (Conn, *response, error) {
	stop := context.AfterFunc(ctx, func() { tc.SetDeadline(time.Now()) }) //nolint:errcheck,gosec // Unblocks the exchange; its own error reports the cancellation.
	req := &http.Request{
		Method:     http.MethodConnect,
		URL:        &url.URL{Host: r.authority},
		Host:       r.authority,
		Header:     r.header,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	err := req.Write(tc)
	var resp *http.Response
	br := bufio.NewReader(tc)
	if err == nil {
		// A 2xx response to CONNECT has no content (RFC 9110 §9.3.6): the tunnel's bytes follow in br,
		// so its Body is never read or closed.
		resp, err = http.ReadResponse(br, req) //nolint:bodyclose // See above; refusals are closed by readRefusal.
	}
	if !stop() {
		err = errors.Join(err, context.Cause(ctx))
	}
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode/100 != 2 {
		out, rerr := readRefusal(resp)
		return nil, out, rerr
	}
	if derr := tc.SetDeadline(time.Time{}); derr != nil {
		return nil, nil, derr
	}
	pending, err := br.Peek(br.Buffered())
	if err != nil {
		return nil, nil, err
	}
	return &h1Conn{Conn: tc, pending: bytes.Clone(pending)}, &response{StatusCode: resp.StatusCode, Header: resp.Header}, nil
}

func readRefusal(resp *http.Response) (*response, error) {
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxErrorBody))
	return &response{StatusCode: resp.StatusCode, Header: resp.Header, Body: body}, errors.Join(err, resp.Body.Close())
}

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

func (d *Dialer) h2Transport() *http.Transport {
	d.once.Do(func() {
		protocols := new(http.Protocols)
		protocols.SetHTTP2(true)
		nd := d.netDialer()
		d.transport = &http.Transport{
			DialContext:       nd.DialContext,
			TLSClientConfig:   d.tlsConfig("", "h2"),
			Protocols:         protocols,
			ForceAttemptHTTP2: true,
			HTTP2: &http.HTTP2Config{
				MaxReceiveBufferPerStream:     4 << 20,
				MaxReceiveBufferPerConnection: 16 << 20,
				SendPingTimeout:               30 * time.Second,
			},
		}
	})
	return d.transport
}

// CloseIdleConnections closes HTTP/2 connections that carry no tunnel.
func (d *Dialer) CloseIdleConnections() {
	if d.transport != nil {
		d.transport.CloseIdleConnections()
	}
}

func (d *Dialer) doHTTP2(ctx context.Context, r *request) (Conn, *response, error) {
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stop := context.AfterFunc(ctx, cancel)
	pr, pw := io.Pipe()
	req, err := http.NewRequestWithContext(streamCtx, http.MethodConnect, "https://"+r.addr, pr)
	if err != nil {
		stop()
		cancel()
		return nil, nil, err
	}
	req.Host = r.authority
	req.Header = r.header
	resp, err := d.h2Transport().RoundTrip(req)
	stopped := stop()
	if err != nil {
		cancel()
		if !stopped {
			err = errors.Join(err, context.Cause(ctx))
		}
		return nil, nil, errors.Join(err, pw.Close())
	}
	if !stopped {
		cancel()
		return nil, nil, errors.Join(context.Cause(ctx), resp.Body.Close(), pw.Close())
	}
	if resp.StatusCode/100 != 2 {
		out, rerr := readRefusal(resp)
		cancel()
		return nil, out, errors.Join(rerr, pw.Close())
	}
	return &h2Conn{body: resp.Body, pw: pw, cancel: cancel, remote: r.target}, &response{StatusCode: resp.StatusCode, Header: resp.Header}, nil
}

type h2Conn struct {
	body   io.ReadCloser
	pw     *io.PipeWriter
	cancel context.CancelFunc
	remote net.Addr
}

func (c *h2Conn) Read(b []byte) (int, error)  { return c.body.Read(b) }
func (c *h2Conn) Write(b []byte) (int, error) { return c.pw.Write(b) }
func (c *h2Conn) CloseWrite() error           { return c.pw.Close() }

func (c *h2Conn) Close() error {
	err := errors.Join(c.pw.Close(), c.body.Close())
	c.cancel()
	return err
}

func (c *h2Conn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *h2Conn) RemoteAddr() net.Addr             { return c.remote }
func (c *h2Conn) SetDeadline(time.Time) error      { return os.ErrNoDeadline }
func (c *h2Conn) SetReadDeadline(time.Time) error  { return os.ErrNoDeadline }
func (c *h2Conn) SetWriteDeadline(time.Time) error { return os.ErrNoDeadline }

func refused(resp *response) *Error {
	e := &Error{StatusCode: resp.StatusCode, Title: http.StatusText(resp.StatusCode)}
	var p struct {
		Title string `json:"title"`
	}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/problem+json") && json.Unmarshal(resp.Body, &p) == nil && p.Title != "" {
		e.Title = p.Title
	}
	e.AuthError = challengeError(resp.Header.Values("WWW-Authenticate"))
	e.RetryAfter = retryAfter(resp.Header.Get("Retry-After"), time.Now())
	return e
}

// challengeError returns the error auth-param of the DPoP challenge (RFC 9110 §11.6.1).
func challengeError(challenges []string) string {
	for _, c := range challenges {
		scheme, params, _ := strings.Cut(strings.TrimSpace(c), " ")
		if !strings.EqualFold(scheme, dpop.Scheme) {
			continue
		}
		for params != "" {
			var name, value string
			name, value, params = nextParam(params)
			if strings.EqualFold(name, "error") {
				return value
			}
		}
	}
	return ""
}

// nextParam splits the first auth-param, name=token or name=quoted-string, from s.
func nextParam(s string) (name, value, rest string) {
	s = strings.TrimLeft(s, " ,")
	name, s, ok := strings.Cut(s, "=")
	if !ok {
		return "", "", ""
	}
	name = strings.TrimSpace(name)
	s = strings.TrimLeft(s, " ")
	if !strings.HasPrefix(s, `"`) {
		value, rest, _ = strings.Cut(s, ",")
		return name, strings.TrimSpace(value), rest
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\' && i+1 < len(s):
			i++
			b.WriteByte(s[i])
		case c == '"':
			return name, b.String(), s[i+1:]
		default:
			b.WriteByte(c)
		}
	}
	return name, b.String(), ""
}

// retryAfter parses delay-seconds or an HTTP-date (RFC 9110 §10.2.3).
func retryAfter(v string, now time.Time) time.Duration {
	if v == "" {
		return 0
	}
	if secs, err := strconv.ParseUint(v, 10, 32); err == nil {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		return t.Sub(now)
	}
	return 0
}
