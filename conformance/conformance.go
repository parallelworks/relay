// Package conformance checks an authorization server and a relay against SPEC.md from the outside.
// An authorization server implementer runs Run with an Environment that issues tokens from their
// server to a relay they started.
package conformance

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/parallelworks/relay/dpop"
	"github.com/parallelworks/relay/internal/rawconnect"
)

// Grant is what a token must authorize.
type Grant struct {
	Subject string
	// JKT is the RFC 7638 thumbprint of the key the token is bound to.
	JKT    string
	Target netip.AddrPort
}

// Environment is an authorization server and a relay under test.
type Environment interface {
	// Relay returns the relay's address and the roots that verify its certificate.
	Relay() (addr string, roots *x509.CertPool)
	// Issue returns an access token for g, with a new relay_session, and a function that makes the
	// session inactive.
	Issue(t testing.TB, g Grant) (token string, revoke func())
	// Target returns an address the relay may reach that echoes what it receives until the peer
	// half-closes, then half-closes.
	Target() netip.AddrPort
	// RevocationDeadline is how long the relay may take to close a tunnel after its session is revoked.
	RevocationDeadline() time.Duration
}

type check struct {
	name string
	run  func(s *suite, ctx context.Context, t testing.TB, http2 bool) error
}

var checks = []check{
	{"Tunnel", (*suite).tunnel},
	{"SingleUse", (*suite).singleUse},
	{"KeyBinding", (*suite).keyBinding},
	{"BearerRejected", (*suite).bearerRejected},
	{"TargetMismatch", (*suite).targetMismatch},
	{"Revocation", (*suite).revocation},
}

type suite struct {
	env    Environment
	addr   string
	roots  *x509.CertPool
	prover *dpop.Prover
}

func newSuite(env Environment) (*suite, error) {
	key, err := dpop.GenerateKey()
	if err != nil {
		return nil, err
	}
	prover, err := dpop.NewProver(key)
	if err != nil {
		return nil, err
	}
	addr, roots := env.Relay()
	return &suite{env: env, addr: addr, roots: roots, prover: prover}, nil
}

// Run runs every check as a subtest of t, over HTTP/1.1 and HTTP/2.
func Run(t *testing.T, env Environment) {
	s, err := newSuite(env)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			for _, http2 := range []bool{false, true} {
				name := "HTTP/1.1"
				if http2 {
					name = "HTTP/2"
				}
				t.Run(name, func(t *testing.T) {
					if err := c.run(s, t.Context(), t, http2); err != nil {
						t.Fatal(err)
					}
				})
			}
		})
	}
}

func (s *suite) grant() Grant {
	return Grant{Subject: "conformance", JKT: s.prover.Thumbprint(), Target: s.env.Target()}
}

type attempt struct {
	prover    *dpop.Prover
	scheme    string
	authority string
	token     string
	http2     bool
}

func (s *suite) connect(ctx context.Context, a *attempt) (*rawconnect.Response, rawconnect.Conn, error) {
	nonce := ""
	for {
		proof, err := a.prover.Proof(http.MethodConnect, dpop.TargetURI(a.authority), a.token, nonce)
		if err != nil {
			return nil, nil, err
		}
		h := http.Header{}
		h.Set("Authorization", a.scheme+" "+a.token)
		h.Set(dpop.HeaderName, proof)
		resp, conn, err := rawconnect.Do(ctx, &rawconnect.Request{Addr: s.addr, Roots: s.roots, Authority: a.authority, Header: h, HTTP2: a.http2})
		if err != nil {
			return nil, nil, err
		}
		next := resp.Header.Get(dpop.NonceHeaderName)
		if conn != nil || nonce != "" || next == "" || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "use_dpop_nonce") {
			return resp, conn, nil
		}
		nonce = next
	}
}

func refused(resp *rawconnect.Response, conn rawconnect.Conn, status int, authError string) error {
	if conn != nil {
		return errors.Join(fmt.Errorf("tunnel opened, want %d", status), conn.Close())
	}
	if resp.StatusCode != status {
		return fmt.Errorf("status %d, want %d", resp.StatusCode, status)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/problem+json" {
		return fmt.Errorf("Content-Type %q, want application/problem+json", ct)
	}
	if authError != "" && !strings.Contains(resp.Header.Get("WWW-Authenticate"), `error="`+authError+`"`) {
		return fmt.Errorf("WWW-Authenticate %q, want error=%q", resp.Header.Get("WWW-Authenticate"), authError)
	}
	return nil
}

func (s *suite) open(ctx context.Context, t testing.TB, http2 bool) (rawconnect.Conn, func(), error) {
	token, revoke := s.env.Issue(t, s.grant())
	resp, conn, err := s.connect(ctx, &attempt{s.prover, dpop.Scheme, s.env.Target().String(), token, http2})
	if err != nil {
		return nil, nil, err
	}
	if conn == nil {
		return nil, nil, fmt.Errorf("tunnel refused with %d: %s", resp.StatusCode, resp.Body)
	}
	return conn, revoke, nil
}

func (s *suite) tunnel(ctx context.Context, t testing.TB, http2 bool) (err error) {
	conn, _, err := s.open(ctx, t, http2)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, conn.Close()) }()
	payload := []byte(strings.Repeat(rand.Text(), 4096))
	written := make(chan error, 1)
	go func() {
		_, werr := conn.Write(payload)
		if werr == nil {
			werr = conn.CloseWrite()
		}
		written <- werr
	}()
	got, rerr := io.ReadAll(conn)
	if jerr := errors.Join(rerr, <-written); jerr != nil {
		return jerr
	}
	if !bytes.Equal(got, payload) {
		return fmt.Errorf("echoed %d bytes, want the %d sent", len(got), len(payload))
	}
	return nil
}

func (s *suite) singleUse(ctx context.Context, t testing.TB, http2 bool) error {
	token, _ := s.env.Issue(t, s.grant())
	a := &attempt{s.prover, dpop.Scheme, s.env.Target().String(), token, http2}
	resp, conn, err := s.connect(ctx, a)
	if err != nil {
		return err
	}
	if conn == nil {
		return fmt.Errorf("first use refused with %d", resp.StatusCode)
	}
	if cerr := conn.Close(); cerr != nil {
		return cerr
	}
	resp, conn, err = s.connect(ctx, a)
	if err != nil {
		return err
	}
	return refused(resp, conn, http.StatusUnauthorized, "invalid_token")
}

func (s *suite) keyBinding(ctx context.Context, t testing.TB, http2 bool) error {
	key, err := dpop.GenerateKey()
	if err != nil {
		return err
	}
	other, err := dpop.NewProver(key)
	if err != nil {
		return err
	}
	token, _ := s.env.Issue(t, s.grant())
	resp, conn, err := s.connect(ctx, &attempt{other, dpop.Scheme, s.env.Target().String(), token, http2})
	if err != nil {
		return err
	}
	return refused(resp, conn, http.StatusUnauthorized, "invalid_token")
}

func (s *suite) bearerRejected(ctx context.Context, t testing.TB, http2 bool) error {
	token, _ := s.env.Issue(t, s.grant())
	resp, conn, err := s.connect(ctx, &attempt{s.prover, "Bearer", s.env.Target().String(), token, http2})
	if err != nil {
		return err
	}
	return refused(resp, conn, http.StatusUnauthorized, "invalid_token")
}

func (s *suite) targetMismatch(ctx context.Context, t testing.TB, http2 bool) error {
	target := s.env.Target()
	token, _ := s.env.Issue(t, s.grant())
	other := netip.AddrPortFrom(target.Addr(), target.Port()^1)
	resp, conn, err := s.connect(ctx, &attempt{s.prover, dpop.Scheme, other.String(), token, http2})
	if err != nil {
		return err
	}
	return refused(resp, conn, http.StatusForbidden, "")
}

func (s *suite) revocation(ctx context.Context, t testing.TB, http2 bool) (err error) {
	conn, revoke, err := s.open(ctx, t, http2)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, conn.Close()) }()
	if _, err := conn.Write([]byte("x")); err != nil {
		return err
	}
	if _, err := io.ReadFull(conn, make([]byte, 1)); err != nil {
		return err
	}
	revoke()
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		if _, err := io.Copy(io.Discard, conn); err != nil {
			return
		}
	}()
	timer := time.NewTimer(s.env.RevocationDeadline())
	defer timer.Stop()
	select {
	case <-ended:
		return nil
	case <-timer.C:
		return fmt.Errorf("tunnel still open %v after revocation", s.env.RevocationDeadline())
	}
}
