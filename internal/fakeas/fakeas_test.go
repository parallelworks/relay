package fakeas

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"go.uber.org/goleak"

	"github.com/parallelworks/relay/dpop"
	"github.com/parallelworks/relay/introspect"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

type harness struct {
	as   *AS
	http *http.Client
	key  *ecdsa.PrivateKey
	id   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	as := New(t)
	hc := introspect.NewHTTPClient(as.Pool())
	t.Cleanup(hc.CloseIdleConnections)
	key, err := dpop.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return &harness{as: as, http: hc, key: key, id: as.AddClient(&key.PublicKey)}
}

func (h *harness) assertion(t *testing.T, key *ecdsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func (h *harness) claims() map[string]any {
	now := time.Now().Unix()
	return map[string]any{"iss": h.id, "sub": h.id, "aud": h.as.Issuer(), "iat": now, "exp": now + 60, "jti": rand.Text()}
}

func (h *harness) post(t *testing.T, path, contentType, body string, header map[string]string) (status int, out map[string]any) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, h.as.Issuer()+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", contentType)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := h.http.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil {
			t.Error(cerr)
		}
	}()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("response %q: %v", raw, err)
	}
	return resp.StatusCode, out
}

func (h *harness) introspect(t *testing.T, assertion, token string) (status int, out map[string]any) {
	t.Helper()
	form := url.Values{"token": {token}, "client_assertion_type": {jwtBearer}, "client_assertion": {assertion}}
	return h.post(t, "/introspect", "application/x-www-form-urlencoded", form.Encode(), nil)
}

func TestMetadata(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	meta, err := introspect.Discover(t.Context(), h.http, h.as.Issuer())
	if err != nil {
		t.Fatal(err)
	}
	if meta.IntrospectionEndpoint != h.as.Issuer()+"/introspect" || meta.RegistrationEndpoint != h.as.Issuer()+"/register" {
		t.Fatalf("metadata %+v", meta)
	}
}

func TestIntrospection(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	g := Grant{
		Subject: "alice", Audience: []string{h.id}, JKT: "j", Target: "10.0.0.1:22", Session: "s1",
		Expires: time.Now().Add(time.Minute), Override: map[string]any{"extra": 1, "token_type": nil},
	}
	tok := h.as.Issue(&g)
	status, body := h.introspect(t, h.assertion(t, h.key, h.claims()), tok)
	if status != http.StatusOK || body["active"] != true || body["extra"] != float64(1) || body["relay_session"] != "s1" {
		t.Fatalf("grant: %d %v", status, body)
	}
	if _, ok := body["token_type"]; ok {
		t.Fatal("override did not remove token_type")
	}
	if _, body := h.introspect(t, h.assertion(t, h.key, h.claims()), tok); body["active"] != false {
		t.Fatalf("second use of a grant: %v", body)
	}
	if _, body := h.introspect(t, h.assertion(t, h.key, h.claims()), "s1"); body["active"] != true || body["sub"] != "alice" {
		t.Fatalf("session: %v", body)
	}
	h.as.SetSession("s1", "alice", false)
	if _, body := h.introspect(t, h.assertion(t, h.key, h.claims()), "s1"); body["active"] != false {
		t.Fatalf("revoked session: %v", body)
	}
	if n := h.as.Introspections(); n != 3+1 {
		t.Fatalf("Introspections = %d", n)
	}
	if n := len(h.as.Assertions()); n != 4 {
		t.Fatalf("Assertions = %d", n)
	}
}

func TestClientAuthenticationFailures(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	other, err := dpop.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	mutate := func(k string, v any) map[string]any {
		c := h.claims()
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		return c
	}
	replayed := h.assertion(t, h.key, h.claims())
	if status, _ := h.introspect(t, replayed, "x"); status != http.StatusOK {
		t.Fatalf("first use of an assertion: %d", status)
	}
	now := time.Now().Unix()
	for name, assertion := range map[string]string{
		"replayed":        replayed,
		"garbage":         "not-a-jws",
		"unknown client":  h.assertion(t, h.key, mutate("iss", "nobody")),
		"wrong key":       h.assertion(t, other, h.claims()),
		"sub differs":     h.assertion(t, h.key, mutate("sub", "someone")),
		"wrong audience":  h.assertion(t, h.key, mutate("aud", h.as.Issuer()+"/introspect")),
		"expired":         h.assertion(t, h.key, mutate("exp", now-1)),
		"too long-lived":  h.assertion(t, h.key, mutate("exp", now+3600)),
		"no jti":          h.assertion(t, h.key, mutate("jti", nil)),
		"payload not obj": signRaw(t, h.key, []byte(`"x"`)),
	} {
		if status, body := h.introspect(t, assertion, "x"); status != http.StatusUnauthorized || body["error"] != "invalid_client" {
			t.Errorf("%s: %d %v", name, status, body)
		}
	}
	form := url.Values{"token": {"x"}, "client_assertion_type": {"urn:other"}, "client_assertion": {h.assertion(t, h.key, h.claims())}}
	if status, _ := h.post(t, "/introspect", "application/x-www-form-urlencoded", form.Encode(), nil); status != http.StatusUnauthorized {
		t.Errorf("wrong assertion type: %d", status)
	}
	if status, _ := h.post(t, "/introspect", "application/x-www-form-urlencoded", "%zz", nil); status != http.StatusBadRequest {
		t.Errorf("malformed form: %d", status)
	}
}

func signRaw(t *testing.T, key *ecdsa.PrivateKey, payload []byte) string {
	t.Helper()
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	s, err := jws.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestRegistration(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	public, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &h.key.PublicKey}}})
	if err != nil {
		t.Fatal(err)
	}
	private, err := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: h.key}}})
	if err != nil {
		t.Fatal(err)
	}
	body := func(jwks []byte, method string) string {
		return `{"token_endpoint_auth_method":"` + method + `","jwks":` + string(jwks) + `}`
	}
	bearer := func() map[string]string {
		return map[string]string{"Authorization": "Bearer " + h.as.InitialAccessToken()}
	}

	status, out := h.post(t, "/register", "application/json", body(public, "private_key_jwt"), bearer())
	if status != http.StatusCreated || out["client_id"] == "" || len(h.as.Registrations()) != 1 {
		t.Fatalf("registration: %d %v", status, out)
	}
	for name, c := range map[string]struct {
		body   string
		header map[string]string
		status int
	}{
		"no token":      {body(public, "private_key_jwt"), nil, http.StatusUnauthorized},
		"reused token":  {body(public, "private_key_jwt"), map[string]string{"Authorization": "Bearer reused"}, http.StatusUnauthorized},
		"not json":      {"{", bearer(), http.StatusBadRequest},
		"private key":   {body(private, "private_key_jwt"), bearer(), http.StatusBadRequest},
		"secret method": {body(public, "client_secret_basic"), bearer(), http.StatusBadRequest},
		"bad jwks":      {`{"token_endpoint_auth_method":"private_key_jwt","jwks":{"keys":5}}`, bearer(), http.StatusBadRequest},
		"unmarshalable": {`{"jwks":1e999}`, bearer(), http.StatusBadRequest},
	} {
		if status, _ := h.post(t, "/register", "application/json", c.body, c.header); status != c.status {
			t.Errorf("%s: %d, want %d", name, status, c.status)
		}
	}
}

func TestHandleOverridesEndpoints(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.as.Handle(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusTeapot, map[string]any{"error": "teapot"})
	})
	if status, _ := h.post(t, "/register", "application/json", "{}", nil); status != http.StatusTeapot {
		t.Fatalf("override not applied: %d", status)
	}
	h.as.Handle(nil)
	if status, _ := h.post(t, "/register", "application/json", "{}", nil); status != http.StatusUnauthorized {
		t.Fatalf("override not removed: %d", status)
	}
}

func TestWriteJSONPanicsOnUnencodableValue(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("no panic")
		}
	}()
	writeJSON(httptest.NewRecorder(), http.StatusOK, map[string]any{"c": make(chan int)})
}
