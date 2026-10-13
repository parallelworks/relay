package introspect

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/parallelworks/relay/dpop"
	"github.com/parallelworks/relay/internal/fakeas"
	"github.com/parallelworks/relay/internal/testpki"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

type env struct {
	as     *fakeas.AS
	client *Client
	id     string
	http   *http.Client
}

func setup(t *testing.T) *env {
	t.Helper()
	as := fakeas.New(t)
	hc := NewHTTPClient(as.Pool())
	t.Cleanup(hc.CloseIdleConnections)
	meta, err := Discover(t.Context(), hc, as.Issuer())
	if err != nil {
		t.Fatal(err)
	}
	key, err := dpop.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	id := as.AddClient(&key.PublicKey)
	c, err := NewClient(meta, Credentials{ClientID: id, KeyID: "k1", Key: key}, hc)
	if err != nil {
		t.Fatal(err)
	}
	return &env{as: as, client: c, id: id, http: hc}
}

func (e *env) grant() *fakeas.Grant {
	return &fakeas.Grant{
		Subject:  "alice",
		Audience: []string{e.id},
		JKT:      "thumbprint",
		Target:   "10.0.0.1:22",
		Session:  "session-" + rand.Text(),
		Expires:  time.Now().Add(time.Minute),
	}
}

func (e *env) introspect(t *testing.T, g *fakeas.Grant) (Token, error) {
	t.Helper()
	return e.client.AccessToken(t.Context(), e.as.Issue(g))
}

func (e *env) respond(body, contentType string, status int) {
	e.as.Handle(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", contentType)
		w.WriteHeader(status)
		if _, err := w.Write([]byte(body)); err != nil {
			panic(err)
		}
	})
}

func TestAccessTokenAccepted(t *testing.T) {
	t.Parallel()
	e := setup(t)
	g := e.grant()
	tok, err := e.introspect(t, g)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Subject != "alice" || tok.JKT != "thumbprint" || tok.Target.String() != "10.0.0.1:22" ||
		tok.Session != g.Session || !tok.Expires.Equal(time.Unix(g.Expires.Unix(), 0)) {
		t.Fatalf("unexpected token %+v", tok)
	}
	if e.client.ClientID() != e.id {
		t.Fatal("ClientID")
	}
	for _, tt := range []any{"DPoP", "dpop", nil} {
		g := e.grant()
		g.Override = map[string]any{"token_type": tt, "aud": e.id}
		if _, err := e.introspect(t, g); err != nil {
			t.Errorf("token_type %v with a string aud: %v", tt, err)
		}
	}
}

func TestNeverCachesResponses(t *testing.T) {
	t.Parallel()
	e := setup(t)
	tok := e.as.Issue(e.grant())
	if _, err := e.client.AccessToken(t.Context(), tok); err != nil {
		t.Fatal(err)
	}
	if _, err := e.client.AccessToken(t.Context(), tok); !errors.Is(err, ErrInactive) {
		t.Fatalf("second introspection of a single-use token = %v, want ErrInactive", err)
	}
	if n := e.as.Introspections(); n != 2 {
		t.Fatalf("authorization server saw %d introspections, want 2", n)
	}
}

func TestRejectsInactive(t *testing.T) {
	t.Parallel()
	e := setup(t)
	if _, err := e.client.AccessToken(t.Context(), "unknown"); !errors.Is(err, ErrInactive) {
		t.Fatalf("unknown token: %v", err)
	}
	g := e.grant()
	g.Override = map[string]any{"active": false}
	if _, err := e.introspect(t, g); !errors.Is(err, ErrInactive) {
		t.Fatalf("active false: %v", err)
	}
}

func TestRejectsWrongAudience(t *testing.T) {
	t.Parallel()
	e := setup(t)
	for _, aud := range []any{[]string{"other"}, "other", []string{}, nil} {
		g := e.grant()
		g.Override = map[string]any{"aud": aud}
		if _, err := e.introspect(t, g); !errors.Is(err, ErrInactive) {
			t.Errorf("aud %v: %v", aud, err)
		}
	}
}

func TestRejectsExpired(t *testing.T) {
	t.Parallel()
	e := setup(t)
	g := e.grant()
	g.Expires = time.Now().Add(-time.Second)
	if _, err := e.introspect(t, g); !errors.Is(err, ErrInactive) {
		t.Fatalf("past exp: %v", err)
	}
	g = e.grant()
	g.Override = map[string]any{"exp": nil}
	if _, err := e.introspect(t, g); !errors.Is(err, ErrInactive) {
		t.Fatalf("missing exp: %v", err)
	}
}

func TestRejectsMissingConfirmation(t *testing.T) {
	t.Parallel()
	e := setup(t)
	for _, cnf := range []any{nil, map[string]any{}, map[string]any{"jkt": ""}, map[string]any{"x5t#S256": "x"}} {
		g := e.grant()
		g.Override = map[string]any{"cnf": cnf}
		if _, err := e.introspect(t, g); !errors.Is(err, ErrInactive) {
			t.Errorf("cnf %v: %v", cnf, err)
		}
	}
}

func TestRejectsNonDPoPTokenType(t *testing.T) {
	t.Parallel()
	e := setup(t)
	for _, tt := range []string{"Bearer", "N_A", ""} {
		g := e.grant()
		g.Override = map[string]any{"token_type": tt}
		if _, err := e.introspect(t, g); !errors.Is(err, ErrInactive) {
			t.Errorf("token_type %q: %v", tt, err)
		}
	}
}

func TestRejectsOversizedResponse(t *testing.T) {
	t.Parallel()
	e := setup(t)
	pad := strings.Repeat("x", MaxResponseSize)
	e.respond(`{"active":false,"pad":"`+pad+`"}`, "application/json", http.StatusOK)
	if _, err := e.client.AccessToken(t.Context(), "t"); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("oversized response: %v", err)
	}
	exact := `{"active":false,"pad":""}`
	exact = `{"active":false,"pad":"` + strings.Repeat("x", MaxResponseSize-len(exact)) + `"}`
	e.respond(exact, "application/json", http.StatusOK)
	if _, err := e.client.AccessToken(t.Context(), "t"); !errors.Is(err, ErrInactive) {
		t.Fatalf("response of exactly %d bytes: %v", MaxResponseSize, err)
	}
}

func TestRejectsWrongMemberTypes(t *testing.T) {
	t.Parallel()
	e := setup(t)
	for member, value := range map[string]any{
		"active":        "true",
		"exp":           "soon",
		"aud":           5,
		"cnf":           "jkt",
		"relay_target":  22,
		"relay_session": []string{"a"},
		"token_type":    true,
		"sub":           false,
	} {
		g := e.grant()
		g.Override = map[string]any{member: value}
		if _, err := e.introspect(t, g); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("%s = %v: %v", member, value, err)
		}
	}
	for _, body := range []string{`{"active":true,"exp":1.5}`, `{}`, `{"active":false}{}`, `[]`, `not json`} {
		e.respond(body, "application/json", http.StatusOK)
		if _, err := e.client.AccessToken(t.Context(), "t"); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("body %s: %v", body, err)
		}
	}
}

func TestRejectsMissingRelayMembers(t *testing.T) {
	t.Parallel()
	e := setup(t)
	for member, value := range map[string]any{
		"relay_target":  nil,
		"relay_session": nil,
	} {
		g := e.grant()
		g.Override = map[string]any{member: value}
		if _, err := e.introspect(t, g); !errors.Is(err, ErrInactive) {
			t.Errorf("%s missing: %v", member, err)
		}
	}
	for _, target := range []string{"example.com:22", "10.0.0.1", "", "10.0.0.1:0"} {
		g := e.grant()
		g.Target = target
		if _, err := e.introspect(t, g); !errors.Is(err, ErrInactive) {
			t.Errorf("relay_target %q: %v", target, err)
		}
	}
	for _, session := range []string{"", strings.Repeat("s", MaxSessionSize+1)} {
		g := e.grant()
		g.Override = map[string]any{"relay_session": session}
		if _, err := e.introspect(t, g); !errors.Is(err, ErrInactive) {
			t.Errorf("relay_session of %d bytes: %v", len(session), err)
		}
	}
	g := e.grant()
	g.Override = map[string]any{"relay_session": strings.Repeat("s", MaxSessionSize)}
	if _, err := e.introspect(t, g); err != nil {
		t.Errorf("relay_session of exactly %d bytes: %v", MaxSessionSize, err)
	}
}

func TestResponseStatusAndMediaType(t *testing.T) {
	t.Parallel()
	e := setup(t)
	cases := []struct {
		status      int
		contentType string
		want        error
	}{
		{http.StatusInternalServerError, "application/json", ErrUnavailable},
		{http.StatusServiceUnavailable, "text/plain", ErrUnavailable},
		{http.StatusUnauthorized, "application/json", ErrInvalidResponse},
		{http.StatusFound, "application/json", ErrInvalidResponse},
		{http.StatusOK, "text/html", ErrInvalidResponse},
		{http.StatusOK, "", ErrInvalidResponse},
	}
	for _, c := range cases {
		e.respond(`{"active":true}`, c.contentType, c.status)
		if _, err := e.client.AccessToken(t.Context(), "t"); !errors.Is(err, c.want) {
			t.Errorf("status %d %q: %v, want %v", c.status, c.contentType, err, c.want)
		}
	}
	e.respond(`{"active":false}`, "application/json; charset=utf-8", http.StatusOK)
	if _, err := e.client.AccessToken(t.Context(), "t"); !errors.Is(err, ErrInactive) {
		t.Errorf("media type with parameters: %v", err)
	}
	e.as.Handle(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Length", "100")
		w.WriteHeader(http.StatusOK)
	})
	if _, err := e.client.AccessToken(t.Context(), "t"); !errors.Is(err, ErrUnavailable) {
		t.Errorf("truncated body: %v", err)
	}
}

func TestSession(t *testing.T) {
	t.Parallel()
	e := setup(t)
	g := e.grant()
	tok := e.as.Issue(g)
	s, err := e.client.Session(t.Context(), g.Session)
	if err != nil || !s.Active || s.Subject != "alice" {
		t.Fatalf("active session: %+v %v", s, err)
	}
	e.as.SetSession(g.Session, "alice", false)
	if s, err = e.client.Session(t.Context(), g.Session); err != nil || s.Active {
		t.Fatalf("revoked session: %+v %v", s, err)
	}
	if _, err = e.client.AccessToken(t.Context(), tok); err != nil {
		t.Fatalf("access token after session queries: %v", err)
	}
	e.respond(`{"active":true,"sub":"bob","exp":2000000000}`, "application/json", http.StatusOK)
	s, err = e.client.Session(t.Context(), "x")
	if err != nil || s.Subject != "bob" || s.Expires.Unix() != 2000000000 {
		t.Fatalf("session with exp: %+v %v", s, err)
	}
	e.respond(`{}`, "application/json", http.StatusOK)
	if _, err := e.client.Session(t.Context(), "x"); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("session without active: %v", err)
	}
}

func TestClientAssertionClaims(t *testing.T) {
	t.Parallel()
	e := setup(t)
	for range 2 {
		if _, err := e.introspect(t, e.grant()); err != nil {
			t.Fatal(err)
		}
	}
	got := e.as.Assertions()
	if len(got) != 2 {
		t.Fatalf("%d assertions accepted, want 2", len(got))
	}
	for _, c := range got {
		iat, _ := c["iat"].(float64)
		exp, _ := c["exp"].(float64)
		if c["iss"] != e.id || c["sub"] != e.id || c["aud"] != e.as.Issuer() || exp-iat != 60 {
			t.Errorf("assertion claims %v", c)
		}
	}
	if got[0]["jti"] == got[1]["jti"] {
		t.Error("two assertions share a jti")
	}
}

func TestRequiresTLS13(t *testing.T) {
	t.Parallel()
	ca := testpki.New(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	//nolint:gosec // G402: the test needs a server that cannot speak TLS 1.3.
	srv.TLS = &tls.Config{MaxVersion: tls.VersionTLS12, Certificates: []tls.Certificate{ca.Leaf(t, "127.0.0.1")}}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	hc := NewHTTPClient(ca.Pool())
	t.Cleanup(hc.CloseIdleConnections)
	if _, err := Discover(t.Context(), hc, srv.URL); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("TLS 1.2 server: %v", err)
	}
	other := fakeas.New(t)
	if _, err := Discover(t.Context(), NewHTTPClient(testpki.New(t).Pool()), other.Issuer()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("untrusted CA: %v", err)
	}
}

func TestDiscoveryRejectsIssuerMismatch(t *testing.T) {
	t.Parallel()
	e := setup(t)
	for _, issuer := range []string{"https://evil.example", e.as.Issuer() + "/", ""} {
		body, err := json.Marshal(map[string]string{
			"issuer":                 issuer,
			"introspection_endpoint": e.as.Issuer() + "/introspect",
		})
		if err != nil {
			t.Fatal(err)
		}
		e.respond(string(body), "application/json", http.StatusOK)
		if _, err := Discover(t.Context(), e.http, e.as.Issuer()); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("issuer %q: %v", issuer, err)
		}
	}
	e.respond("{", "application/json", http.StatusOK)
	if _, err := Discover(t.Context(), e.http, e.as.Issuer()); !errors.Is(err, ErrInvalidResponse) {
		t.Errorf("malformed metadata: %v", err)
	}
}

func TestDiscoveryRejectsNonHTTPSEndpoints(t *testing.T) {
	t.Parallel()
	e := setup(t)
	for _, m := range []map[string]string{
		{"introspection_endpoint": "http://127.0.0.1/introspect"},
		{"introspection_endpoint": ""},
		{"introspection_endpoint": "https:///nohost"},
		{"introspection_endpoint": e.as.Issuer() + "/i", "registration_endpoint": "http://127.0.0.1/register"},
		{"introspection_endpoint": "%zz"},
	} {
		m["issuer"] = e.as.Issuer()
		body, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		e.respond(string(body), "application/json", http.StatusOK)
		if _, err := Discover(t.Context(), e.http, e.as.Issuer()); !errors.Is(err, ErrInvalidResponse) {
			t.Errorf("metadata %v: %v", m, err)
		}
	}
	body, err := json.Marshal(map[string]string{"issuer": e.as.Issuer(), "introspection_endpoint": e.as.Issuer() + "/i"})
	if err != nil {
		t.Fatal(err)
	}
	e.respond(string(body), "application/json", http.StatusOK)
	if _, err := Discover(t.Context(), e.http, e.as.Issuer()); err != nil {
		t.Errorf("metadata without a registration endpoint: %v", err)
	}
}

func TestMetadataURL(t *testing.T) {
	t.Parallel()
	for issuer, want := range map[string]string{
		"https://as.example":         "https://as.example/.well-known/oauth-authorization-server",
		"https://as.example/":        "https://as.example/.well-known/oauth-authorization-server",
		"https://as.example/tenant1": "https://as.example/.well-known/oauth-authorization-server/tenant1",
	} {
		got, err := MetadataURL(issuer)
		if err != nil || got != want {
			t.Errorf("MetadataURL(%q) = %q, %v; want %q", issuer, got, err, want)
		}
	}
	for _, issuer := range []string{"http://as.example", "https://as.example?x=1", "https://as.example#f", "https://u@as.example", "https://", "%zz"} {
		if _, err := MetadataURL(issuer); err == nil {
			t.Errorf("MetadataURL(%q) accepted", issuer)
		}
	}
	if _, err := Discover(t.Context(), http.DefaultClient, "http://insecure"); err == nil { //nolint:forbidigo // The request is never sent.
		t.Error("Discover accepted an http issuer")
	}
}

func TestNewClient(t *testing.T) {
	t.Parallel()
	p256, err := dpop.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	small := new(rsa.PrivateKey)
	small.N, small.E = new(big.Int).Rsh(rsaKey.N, 1100), 65537
	for _, c := range []struct {
		key  crypto.Signer
		want string
	}{{p256, "ES256"}, {p384, "ES384"}, {rsaKey, "PS256"}} {
		alg, err := SigningAlgorithm(c.key)
		if err != nil || alg != c.want {
			t.Errorf("%T: %q, %v; want %q", c.key, alg, err, c.want)
		}
		if _, err := NewClient(Metadata{}, Credentials{ClientID: "c", Key: c.key}, nil); err != nil {
			t.Errorf("%T: %v", c.key, err)
		}
	}
	if _, err := NewClient(Metadata{}, Credentials{Key: p256}, nil); err == nil {
		t.Error("empty client_id accepted")
	}
	for _, key := range []crypto.Signer{p521, small} {
		if _, err := SigningAlgorithm(key); err == nil {
			t.Errorf("%T accepted", key)
		}
		if _, err := NewClient(Metadata{}, Credentials{ClientID: "c", Key: key}, nil); err == nil {
			t.Errorf("%T accepted by NewClient", key)
		}
	}
}

func TestUnavailableServer(t *testing.T) {
	t.Parallel()
	e := setup(t)
	c, err := NewClient(Metadata{Issuer: e.as.Issuer(), IntrospectionEndpoint: "https://127.0.0.1:1/introspect"},
		Credentials{ClientID: e.id, Key: mustKey(t)}, e.http)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.AccessToken(t.Context(), "t"); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("unreachable server: %v", err)
	}
	bad, err := NewClient(Metadata{IntrospectionEndpoint: "%zz"}, Credentials{ClientID: e.id, Key: mustKey(t)}, e.http)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.AccessToken(t.Context(), "t"); err == nil {
		t.Fatal("unparseable endpoint accepted")
	}
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := dpop.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestAssertionKeyID(t *testing.T) {
	t.Parallel()
	e := setup(t)
	key := mustKey(t)
	id := e.as.AddClient(&key.PublicKey)
	meta, err := Discover(t.Context(), e.http, e.as.Issuer())
	if err != nil {
		t.Fatal(err)
	}
	noKID, err := NewClient(meta, Credentials{ClientID: id, Key: key}, e.http)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.introspect(t, e.grant()); err != nil {
		t.Fatal(err)
	}
	if _, err = noKID.Session(t.Context(), "s"); err != nil {
		t.Fatal(err)
	}
	if got := e.as.AssertionKeyIDs(); len(got) != 2 || got[0] != "k1" || got[1] != "" {
		t.Fatalf("assertion kids %q, want [k1 \"\"]", got)
	}
}

type failingClose struct {
	io.Reader
}

func (failingClose) Close() error {
	return errors.New("close failed")
}

type closeFailingTransport struct {
	base http.RoundTripper
}

func (c closeFailingTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	resp, err := c.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if err := resp.Body.Close(); err != nil {
		return nil, err
	}
	resp.Body = failingClose{Reader: bytes.NewReader(body)}
	return resp, nil
}

func TestBodyCloseErrorIsReported(t *testing.T) {
	t.Parallel()
	e := setup(t)
	hc := NewHTTPClient(e.as.Pool())
	t.Cleanup(hc.CloseIdleConnections)
	hc.Transport = closeFailingTransport{base: hc.Transport}
	if _, err := Discover(t.Context(), hc, e.as.Issuer()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("close error: %v", err)
	}
}
