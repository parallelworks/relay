package conformance

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/parallelworks/relay/internal/fakeas"
	"github.com/parallelworks/relay/internal/rawconnect"
	"github.com/parallelworks/relay/internal/relaytest"
	"github.com/parallelworks/relay/introspect"
	"github.com/parallelworks/relay/server"
)

type brokenEnv struct {
	*relaytest.Env
	addr     string
	target   netip.AddrPort
	token    string
	noRevoke bool
}

func (e *brokenEnv) Relay() (string, *x509.CertPool) {
	if e.addr != "" {
		return e.addr, e.Roots
	}
	return e.Addr, e.Roots
}

func (e *brokenEnv) Target() netip.AddrPort {
	if e.target.IsValid() {
		return e.target
	}
	return e.Echo
}

func (e *brokenEnv) RevocationDeadline() time.Duration { return 200 * time.Millisecond }

func (e *brokenEnv) Issue(_ testing.TB, g Grant) (token string, revoke func()) {
	if e.token != "" {
		return e.token, func() {}
	}
	session := "session-" + rand.Text()
	token = e.AS.Issue(&fakeas.Grant{
		Subject: g.Subject, Audience: []string{e.ClientID}, JKT: g.JKT, Target: g.Target.String(),
		Session: session, Expires: time.Now().Add(time.Minute),
	})
	if e.noRevoke {
		return token, func() {}
	}
	return token, func() { e.AS.SetSession(session, g.Subject, false) }
}

func failures(t *testing.T, env Environment, names ...string) {
	t.Helper()
	s, err := newSuite(env)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	for _, c := range checks {
		err := c.run(s, t.Context(), t, false)
		if want[c.name] && err == nil {
			t.Errorf("%s passed against a broken environment", c.name)
		}
		if !want[c.name] && err != nil {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

type reusable struct {
	inner server.Introspector
	mu    sync.Mutex
	seen  map[string]introspect.Token
}

func (r *reusable) AccessToken(ctx context.Context, token string) (introspect.Token, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if tok, ok := r.seen[token]; ok {
		return tok, nil
	}
	tok, err := r.inner.AccessToken(ctx, token)
	if err == nil {
		r.seen[token] = tok
	}
	return tok, err
}

func TestDetectsReusableTokens(t *testing.T) {
	t.Parallel()
	e := relaytest.Start(t, &relaytest.Options{SessionInterval: 20 * time.Millisecond, WrapIntrospector: func(inner server.Introspector) server.Introspector {
		return &reusable{inner: inner, seen: map[string]introspect.Token{}}
	}})
	failures(t, &brokenEnv{Env: e}, "SingleUse")
}

func TestDetectsIgnoredRevocation(t *testing.T) {
	t.Parallel()
	e := relaytest.Start(t, &relaytest.Options{SessionInterval: 20 * time.Millisecond})
	failures(t, &brokenEnv{Env: e, noRevoke: true}, "Revocation")
}

func TestDetectsUnusableTokens(t *testing.T) {
	t.Parallel()
	e := relaytest.Start(t, &relaytest.Options{SessionInterval: 20 * time.Millisecond})
	failures(t, &brokenEnv{Env: e, token: "unknown"}, "Tunnel", "SingleUse", "TargetMismatch", "Revocation")
}

func TestDetectsATargetThatDoesNotEcho(t *testing.T) {
	t.Parallel()
	e := relaytest.Start(t, &relaytest.Options{SessionInterval: 20 * time.Millisecond})
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			if cerr := c.Close(); cerr != nil {
				t.Log(cerr)
			}
		}
	})
	t.Cleanup(func() {
		if cerr := ln.Close(); cerr != nil {
			t.Error(cerr)
		}
		wg.Wait()
	})
	failures(t, &brokenEnv{Env: e, target: netip.MustParseAddrPort(ln.Addr().String())}, "Tunnel", "Revocation")
}

func TestUnreachableRelay(t *testing.T) {
	t.Parallel()
	e := relaytest.Start(t, &relaytest.Options{SessionInterval: 20 * time.Millisecond})
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	all := make([]string, len(checks))
	for i, c := range checks {
		all[i] = c.name
	}
	failures(t, &brokenEnv{Env: e, addr: addr}, all...)
}

type fakeConn struct{ closeErr error }

func (fakeConn) Read([]byte) (int, error)  { return 0, errors.New("unused") }
func (fakeConn) Write([]byte) (int, error) { return 0, errors.New("unused") }
func (fakeConn) CloseWrite() error         { return nil }
func (c fakeConn) Close() error            { return c.closeErr }

func TestRefused(t *testing.T) {
	t.Parallel()
	problem := http.Header{"Content-Type": {"application/problem+json"}}
	challenge := http.Header{"Content-Type": {"application/problem+json"}, "Www-Authenticate": {`DPoP error="invalid_token"`}}
	cases := []struct {
		name    string
		resp    *rawconnect.Response
		conn    rawconnect.Conn
		status  int
		auth    string
		wantErr string
	}{
		{"opened", nil, fakeConn{}, 401, "", "tunnel opened"},
		{"status", &rawconnect.Response{StatusCode: 403, Header: problem}, nil, 401, "", "status 403"},
		{"media type", &rawconnect.Response{StatusCode: 401, Header: http.Header{}}, nil, 401, "", "Content-Type"},
		{"challenge", &rawconnect.Response{StatusCode: 401, Header: problem}, nil, 401, "invalid_token", "WWW-Authenticate"},
		{"ok", &rawconnect.Response{StatusCode: 401, Header: challenge}, nil, 401, "invalid_token", ""},
	}
	for _, c := range cases {
		err := refused(c.resp, c.conn, c.status, c.auth)
		if c.wantErr == "" && err != nil || c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
