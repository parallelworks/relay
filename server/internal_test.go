package server

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/parallelworks/relay/dpop"
	"github.com/parallelworks/relay/internal/testpki"
	"github.com/parallelworks/relay/introspect"
	"github.com/parallelworks/relay/policy"
	"github.com/parallelworks/relay/session"
	"github.com/parallelworks/relay/tunnel"
)

type noIntrospection struct{}

func (noIntrospection) AccessToken(context.Context, string) (introspect.Token, error) {
	return introspect.Token{}, introspect.ErrInactive
}

func (noIntrospection) Session(context.Context, string) (introspect.Session, error) {
	return introspect.Session{}, introspect.ErrInactive
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	pol, err := policy.New([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(&Config{
		Verifier:       dpop.NewVerifier(dpop.Options{}),
		Introspector:   noIntrospection{},
		Policy:         pol,
		Sessions:       session.NewRegistry(noIntrospection{}, session.Options{}),
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, errors.New("none") },
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestNewRequiresDependencies(t *testing.T) {
	t.Parallel()
	if _, err := New(&Config{}); err == nil {
		t.Fatal("New accepted an empty config")
	}
}

func TestRejectsExtendedConnect(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	r := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "https://10.0.0.1:22", http.NoBody)
	r.URL.Scheme, r.URL.Path = "", ""
	r.Header.Set(":protocol", "websocket")
	r.ProtoMajor = 2
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status %d", w.Code)
	}
	if w.Header().Get("Connection") != "" {
		t.Fatal("Connection field on an HTTP/2 response")
	}
}

func TestRejectsAfterClose(t *testing.T) {
	t.Parallel()
	s := newTestServer(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequestWithContext(t.Context(), http.MethodConnect, "https://10.0.0.1:22", http.NoBody)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") != "1" {
		t.Fatalf("status %d, Retry-After %q", w.Code, w.Header().Get("Retry-After"))
	}
}

func TestCloseReason(t *testing.T) {
	t.Parallel()
	cases := map[error]string{
		nil:                                     CloseEOF,
		errStreamEnded:                          CloseEOF,
		session.ErrRevoked:                      CloseRevoked,
		session.ErrSubjectMismatch:              CloseSubjectMismatch,
		session.ErrExpired:                      CloseExpired,
		session.ErrNoAnswer:                     CloseUnverified,
		tunnel.ErrIdle:                          CloseIdle,
		tunnel.ErrLifetime:                      CloseLifetime,
		fmt.Errorf("%w: boom", tunnel.ErrPanic): ClosePanic,
		ErrClosed:                               CloseShutdown,
		errors.New("reset"):                     CloseError,
	}
	for err, want := range cases {
		if got := closeReason(err); got != want {
			t.Errorf("closeReason(%v) = %q, want %q", err, got, want)
		}
	}
}

func TestTokenIDIsAHashPrefix(t *testing.T) {
	t.Parallel()
	if got := TokenID("token"); got != "3c469e9d" {
		t.Fatalf("TokenID = %q", got)
	}
}

func TestNopObserver(t *testing.T) {
	t.Parallel()
	var o Observer = nopObserver{}
	o.TunnelOpened(t.Context(), &Tunnel{})
	o.TunnelClosed(t.Context(), &Closed{})
	o.TunnelRejected(t.Context(), Rejection{})
}

func TestSourceGrouping(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"192.0.2.1:1234":              "192.0.2.1/32",
		"[::ffff:192.0.2.1]:1234":     "192.0.2.1/32",
		"[2001:db8:1:2:3:4:5:6]:1234": "2001:db8:1:2::/64",
		"not an address":              "invalid Prefix",
	}
	for in, want := range cases {
		if got := sourceOf(in).String(); got != want {
			t.Errorf("sourceOf(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestFailureLimiter(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_000_000, 0)
	a := netip.MustParsePrefix("192.0.2.1/32")
	b := netip.MustParsePrefix("192.0.2.2/32")
	f := newFailureLimiter(2, 1)
	if _, ok := f.allow(a, now); !ok {
		t.Fatal("unknown source refused")
	}
	f.fail(a, now)
	if _, ok := f.allow(a, now); !ok {
		t.Fatal("refused after one failure of two")
	}
	f.fail(a, now)
	wait, ok := f.allow(a, now)
	if ok || wait != 30*time.Second {
		t.Fatalf("allow = %v, %v; want refusal for 30s", wait, ok)
	}
	f.fail(a, now)
	if wait, _ := f.allow(a, now); wait != 30*time.Second {
		t.Fatalf("tokens went below zero: wait %v", wait)
	}
	if _, ok := f.allow(a, now.Add(29*time.Second)); ok {
		t.Fatal("allowed before a token refilled")
	}
	if _, ok := f.allow(a, now.Add(30*time.Second)); !ok {
		t.Fatal("refused after a token refilled")
	}

	f.fail(b, now.Add(30*time.Second))
	if _, ok := f.buckets[b]; ok {
		t.Fatal("tracked a source beyond the limit while the table held a partial bucket")
	}
	f.fail(b, now.Add(2*time.Minute))
	if _, ok := f.buckets[b]; !ok {
		t.Fatal("full buckets were not pruned to make room")
	}
	if _, ok := f.buckets[a]; ok {
		t.Fatal("refilled bucket kept")
	}
}

func writePair(t *testing.T, ca *testpki.CA, dir string) {
	t.Helper()
	certPEM, keyPEM := ca.LeafPEM(t, "127.0.0.1")
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestLoadCertificatesErrors(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if _, err := LoadCertificates(filepath.Join(dir, "missing"), "tls.crt", "tls.key"); err == nil {
		t.Fatal("missing directory accepted")
	}
	if _, err := LoadCertificates(dir, "tls.crt", "tls.key"); err == nil {
		t.Fatal("missing certificate accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCertificates(dir, "tls.crt", "tls.key"); err == nil {
		t.Fatal("missing key accepted")
	}
	if err := os.WriteFile(filepath.Join(dir, "tls.key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCertificates(dir, "tls.crt", "tls.key"); err == nil {
		t.Fatal("invalid PEM accepted")
	}
	if _, err := LoadCertificates(dir, "../tls.crt", "tls.key"); err == nil {
		t.Fatal("path outside the directory accepted")
	}
}

func served(t *testing.T, c *Certificates) *tls.Certificate {
	t.Helper()
	cert, err := c.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestWatchReloadsChangedCertificates(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		dir := t.TempDir()
		ca := testpki.New(t)
		writePair(t, ca, dir)
		c, err := LoadCertificates(dir, "tls.crt", "tls.key")
		if err != nil {
			t.Fatal(err)
		}
		defer func() {
			if err := c.Close(); err != nil {
				t.Error(err)
			}
		}()
		first := served(t, c)
		var logs bytes.Buffer
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan struct{})
		go func() {
			defer close(done)
			c.Watch(ctx, time.Minute, slog.New(slog.NewTextHandler(&logs, nil)))
		}()

		writePair(t, ca, dir)
		time.Sleep(time.Minute)
		synctest.Wait()
		second := served(t, c)
		if second == first {
			t.Fatal("certificate not reloaded")
		}
		if err := os.WriteFile(filepath.Join(dir, "tls.crt"), []byte("garbage"), 0o600); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Minute)
		synctest.Wait()
		if served(t, c) != second {
			t.Fatal("a failed reload replaced the certificate")
		}
		cancel()
		<-done
		out := logs.String()
		if !strings.Contains(out, "certificate.reloaded") || !strings.Contains(out, "certificate.reload_failed") {
			t.Fatalf("logs: %s", out)
		}
	})
}
