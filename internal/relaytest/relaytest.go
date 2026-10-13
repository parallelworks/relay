// Package relaytest runs a relay server against the fake authorization server and an echo target
// on loopback, for tests.
package relaytest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/parallelworks/relay/dpop"
	"github.com/parallelworks/relay/internal/fakeas"
	"github.com/parallelworks/relay/internal/rawconnect"
	"github.com/parallelworks/relay/internal/testpki"
	"github.com/parallelworks/relay/introspect"
	"github.com/parallelworks/relay/policy"
	"github.com/parallelworks/relay/server"
	"github.com/parallelworks/relay/session"
)

// Certificate and key file names in Env.CertDir.
const (
	CertFile = "tls.crt"
	KeyFile  = "tls.key"
)

// Options configure Start. Zero values use defaults suited to tests.
type Options struct {
	Limits           server.Limits
	Nonces           bool
	MaxReplayEntries int
	SessionInterval  time.Duration
	SessionGrace     time.Duration
	Observer         server.Observer
	// WrapIntrospector wraps the introspection client the relay uses for access tokens.
	WrapIntrospector func(server.Introspector) server.Introspector
}

// Env is a running relay with its authorization server, echo target and client key.
type Env struct {
	AS       *fakeas.AS
	Server   *server.Server
	Certs    *server.Certificates
	CA       *testpki.CA
	CertDir  string
	Addr     string
	Roots    *x509.CertPool
	Echo     netip.AddrPort
	Prover   *dpop.Prover
	Key      *ecdsa.PrivateKey
	ClientID string
	Sessions *session.Registry
	Logs     *Buffer
}

// Buffer is a concurrency-safe log sink.
type Buffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *Buffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

// String returns everything written so far.
func (b *Buffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Start runs a relay that the test stops when it ends.
func Start(t testing.TB, opts *Options) *Env {
	t.Helper()
	e := &Env{AS: fakeas.New(t), CA: testpki.New(t), CertDir: t.TempDir(), Logs: &Buffer{}}
	e.Roots = e.CA.Pool()
	e.WriteCertificate(t)
	certs, err := server.LoadCertificates(e.CertDir, CertFile, KeyFile)
	must(t, err)
	t.Cleanup(func() { must(t, certs.Close()) })
	e.Certs = certs

	hc := introspect.NewHTTPClient(e.AS.Pool())
	t.Cleanup(hc.CloseIdleConnections)
	meta, err := introspect.Discover(t.Context(), hc, e.AS.Issuer())
	must(t, err)
	relayKey, err := dpop.GenerateKey()
	must(t, err)
	e.ClientID = e.AS.AddClient(&relayKey.PublicKey)
	ic, err := introspect.NewClient(meta, introspect.Credentials{ClientID: e.ClientID, KeyID: "relay", Key: relayKey}, hc)
	must(t, err)

	var nonces *dpop.Nonces
	if opts.Nonces {
		nonces, err = dpop.NewRandomNonces(time.Minute)
		must(t, err)
	}
	pol, err := policy.New([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, []netip.Addr{netip.MustParseAddr("127.0.0.1")})
	must(t, err)
	e.Sessions = session.NewRegistry(ic, session.Options{Interval: opts.SessionInterval, Grace: opts.SessionGrace})
	var intro server.Introspector = ic
	if opts.WrapIntrospector != nil {
		intro = opts.WrapIntrospector(ic)
	}
	e.Server, err = server.New(&server.Config{
		Verifier:       dpop.NewVerifier(dpop.Options{Nonces: nonces, MaxReplayEntries: opts.MaxReplayEntries}),
		Nonces:         nonces,
		Introspector:   intro,
		Policy:         pol,
		Sessions:       e.Sessions,
		GetCertificate: certs.GetCertificate,
		Logger:         slog.New(slog.NewJSONHandler(e.Logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Observer:       opts.Observer,
		Limits:         opts.Limits,
	})
	must(t, err)

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	must(t, err)
	e.Addr = ln.Addr().String()
	served := make(chan error, 1)
	go func() { served <- e.Server.Serve(ln) }()
	t.Cleanup(func() {
		must(t, e.Server.Close())
		if serr := <-served; !errors.Is(serr, http.ErrServerClosed) {
			t.Error(serr)
		}
	})

	e.Echo = StartEcho(t)
	e.Key, err = dpop.GenerateKey()
	must(t, err)
	e.Prover, err = dpop.NewProver(e.Key)
	must(t, err)
	return e
}

// WriteCertificate writes a new relay certificate for 127.0.0.1 into CertDir.
func (e *Env) WriteCertificate(t testing.TB) {
	t.Helper()
	certPEM, keyPEM := e.CA.LeafPEM(t, "127.0.0.1")
	must(t, os.WriteFile(filepath.Join(e.CertDir, KeyFile), keyPEM, 0o600))
	must(t, os.WriteFile(filepath.Join(e.CertDir, CertFile), certPEM, 0o600))
}

// StartEcho runs a TCP echo server on 127.0.0.1 that echoes until the peer half-closes, then
// half-closes back.
func StartEcho(t testing.TB) netip.AddrPort {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	must(t, err)
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			wg.Go(func() { echo(t, c.(*net.TCPConn)) })
		}
	})
	t.Cleanup(func() {
		must(t, ln.Close())
		wg.Wait()
	})
	return netip.MustParseAddrPort(ln.Addr().String())
}

func echo(t testing.TB, c *net.TCPConn) {
	_, err := io.Copy(c, c)
	if err == nil {
		err = c.CloseWrite()
	}
	if err == nil {
		_, err = io.Copy(io.Discard, c)
	}
	if err = errors.Join(err, c.Close()); err != nil {
		t.Log("echo:", err)
	}
}

// Grant returns a grant for target bound to the env's client key, with a fresh session.
func (e *Env) Grant(target netip.AddrPort) *fakeas.Grant {
	return &fakeas.Grant{
		Subject:  "alice",
		Audience: []string{e.ClientID},
		JKT:      e.Prover.Thumbprint(),
		Target:   target.String(),
		Session:  "session-" + rand.Text(),
		Expires:  time.Now().Add(time.Minute),
	}
}

// Header returns the Authorization and DPoP fields for a CONNECT to authority.
func (e *Env) Header(t testing.TB, authority, token, nonce string) http.Header {
	t.Helper()
	proof, err := e.Prover.Proof(http.MethodConnect, dpop.TargetURI(authority), token, nonce)
	must(t, err)
	h := http.Header{}
	h.Set("Authorization", dpop.Scheme+" "+token)
	h.Set(dpop.HeaderName, proof)
	return h
}

// Connect sends a well-formed CONNECT to authority, answering one nonce challenge.
func (e *Env) Connect(ctx context.Context, t testing.TB, authority, token string, http2 bool) (*rawconnect.Response, rawconnect.Conn) {
	t.Helper()
	resp, conn := e.Raw(ctx, t, authority, e.Header(t, authority, token, ""), http2)
	nonce := resp.Header.Get(dpop.NonceHeaderName)
	if conn != nil || nonce == "" {
		return resp, conn
	}
	return e.Raw(ctx, t, authority, e.Header(t, authority, token, nonce), http2)
}

// Raw sends a CONNECT with exactly the given header fields.
func (e *Env) Raw(ctx context.Context, t testing.TB, authority string, h http.Header, http2 bool) (*rawconnect.Response, rawconnect.Conn) {
	t.Helper()
	resp, conn, err := rawconnect.Do(ctx, &rawconnect.Request{Addr: e.Addr, Roots: e.Roots, Authority: authority, Header: h, HTTP2: http2})
	must(t, err)
	return resp, conn
}
