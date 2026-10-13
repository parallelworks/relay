package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/parallelworks/relay/dpop"
	"github.com/parallelworks/relay/introspect"
	"github.com/parallelworks/relay/policy"
	"github.com/parallelworks/relay/session"
)

type fuzzIntrospector struct{}

func (fuzzIntrospector) AccessToken(context.Context, string) (introspect.Token, error) {
	return introspect.Token{}, introspect.ErrInactive
}

func (fuzzIntrospector) Session(context.Context, string) (introspect.Session, error) {
	return introspect.Session{}, introspect.ErrInactive
}

func FuzzConnectRequest(f *testing.F) {
	f.Add("CONNECT", "10.0.0.1:22", "DPoP abc", "a.b.c")
	f.Add("CONNECT", "[2001:db8::1]:22", "Bearer abc", "")
	f.Add("GET", "example.com:443", "", "")
	f.Add("CONNECT", "10.0.0.1:22", "DPoP abc\x00", "x\ny")
	pol, err := policy.New([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, nil)
	if err != nil {
		f.Fatal(err)
	}
	s, err := New(&Config{
		Verifier:       dpop.NewVerifier(dpop.Options{}),
		Introspector:   fuzzIntrospector{},
		Policy:         pol,
		Sessions:       session.NewRegistry(fuzzIntrospector{}, session.Options{}),
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, errors.New("none") },
		Limits:         Limits{FailedAuthPerMinute: 1 << 30},
	})
	if err != nil {
		f.Fatal(err)
	}
	allowed := map[int]bool{
		http.StatusBadRequest:      true,
		http.StatusUnauthorized:    true,
		http.StatusTooManyRequests: true,
	}
	f.Fuzz(func(t *testing.T, method, authority, authorization, proof string) {
		h := http.Header{}
		if authorization != "" {
			h.Set("Authorization", authorization)
		}
		if proof != "" {
			h.Set(dpop.HeaderName, proof)
		}
		r := &http.Request{
			Method:     method,
			URL:        &url.URL{Host: authority},
			Host:       authority,
			Header:     h,
			RemoteAddr: "192.0.2.1:1234",
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
			Body:       http.NoBody,
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if !allowed[w.Code] {
			t.Fatalf("status %d for %q %q %q %q", w.Code, method, authority, authorization, proof)
		}
		if body := w.Body.String(); !strings.HasPrefix(body, `{"type":"about:blank","title":"`) {
			t.Fatalf("body %s", body)
		}
		if w.Code == http.StatusUnauthorized && !strings.HasPrefix(w.Header().Get("WWW-Authenticate"), "DPoP ") {
			t.Fatal("401 without a DPoP challenge")
		}
		if s.Tunnels() != 0 {
			t.Fatal("request still counted after it ended")
		}
	})
}
