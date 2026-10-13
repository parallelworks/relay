// Package fakeas is an in-memory OAuth 2.0 authorization server for tests. It serves metadata
// (RFC 8414), introspection (RFC 7662) with private_key_jwt client authentication (RFC 7523), and
// dynamic client registration (RFC 7591).
package fakeas

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/parallelworks/relay/internal/testpki"
)

const jwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" //nolint:gosec // G101: a registered URN, not a credential.

var algorithms = []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.PS256}

// Grant describes the token an introspection of an access token reports.
type Grant struct {
	Subject  string
	Audience []string
	JKT      string
	Target   string
	Session  string
	Expires  time.Time
	// Override replaces or adds members in the introspection response. A nil value removes the member.
	Override map[string]any
}

// AS is a running fake authorization server.
type AS struct {
	srv    *httptest.Server
	ca     *testpki.CA
	issuer string

	mu             sync.Mutex
	clients        map[string]*jose.JSONWebKey
	initialTokens  map[string]bool
	grants         map[string]Grant
	sessions       map[string]sessionState
	seenAssertions map[string]bool
	assertions     []map[string]any
	assertionKIDs  []string
	introspections int
	registrations  []map[string]any
	handler        http.HandlerFunc
}

type sessionState struct {
	active  bool
	subject string
}

// New starts a fake authorization server that is stopped when the test ends.
func New(t testing.TB) *AS {
	t.Helper()
	a := &AS{
		ca:             testpki.New(t),
		clients:        map[string]*jose.JSONWebKey{},
		initialTokens:  map[string]bool{},
		grants:         map[string]Grant{},
		sessions:       map[string]sessionState{},
		seenAssertions: map[string]bool{},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", a.metadata)
	mux.HandleFunc("POST /introspect", a.introspect)
	mux.HandleFunc("POST /register", a.register)
	a.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a.mu.Lock()
		h := a.handler
		a.mu.Unlock()
		if h != nil {
			h(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	}))
	a.srv.TLS = a.ca.ServerConfig(t)
	a.srv.StartTLS()
	a.issuer = a.srv.URL
	t.Cleanup(a.srv.Close)
	return a
}

// Issuer returns the issuer identifier.
func (a *AS) Issuer() string {
	return a.issuer
}

// Pool returns a certificate pool that trusts the server.
func (a *AS) Pool() *x509.CertPool {
	return a.ca.Pool()
}

// CAPEM returns the PEM certificate of the CA that issued the server's certificate.
func (a *AS) CAPEM() []byte {
	return a.ca.CertPEM()
}

// Handle replaces every endpoint with h, to simulate a misbehaving server. Pass nil to restore.
func (a *AS) Handle(h http.HandlerFunc) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.handler = h
}

// InitialAccessToken returns a new single-use registration token.
func (a *AS) InitialAccessToken() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	tok := rand.Text()
	a.initialTokens[tok] = true
	return tok
}

// AddClient registers a client with key directly and returns its client_id.
func (a *AS) AddClient(key crypto.PublicKey) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	id := rand.Text()
	a.clients[id] = &jose.JSONWebKey{Key: key}
	return id
}

// Issue records g and returns a new access token for it. The token is single use. The grant's
// session, when set, starts active.
func (a *AS) Issue(g *Grant) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	tok := rand.Text()
	a.grants[tok] = *g
	if g.Session != "" {
		a.sessions[g.Session] = sessionState{active: true, subject: g.Subject}
	}
	return tok
}

// SetSession sets whether session is active and which subject it reports.
func (a *AS) SetSession(session, subject string, active bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.sessions[session] = sessionState{active: active, subject: subject}
}

// Introspections returns how many introspection requests were authenticated.
func (a *AS) Introspections() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.introspections
}

// Assertions returns the claims of every client assertion the server accepted.
func (a *AS) Assertions() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]map[string]any(nil), a.assertions...)
}

// AssertionKeyIDs returns the kid header of every client assertion the server accepted.
func (a *AS) AssertionKeyIDs() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.assertionKIDs...)
}

// Registrations returns the bodies of every successful registration request.
func (a *AS) Registrations() []map[string]any {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]map[string]any(nil), a.registrations...)
}

func (a *AS) metadata(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                 a.issuer,
		"introspection_endpoint": a.issuer + "/introspect",
		"registration_endpoint":  a.issuer + "/register",
		"introspection_endpoint_auth_methods_supported":            []string{"private_key_jwt"},
		"introspection_endpoint_auth_signing_alg_values_supported": []string{"ES256", "ES384", "PS256"},
	})
}

func (a *AS) introspect(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
		return
	}
	if err := a.authenticate(r.PostForm); err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_client", "error_description": err.Error()})
		return
	}
	token := r.PostForm.Get("token")
	a.mu.Lock()
	a.introspections++
	g, isGrant := a.grants[token]
	delete(a.grants, token)
	s, isSession := a.sessions[token]
	a.mu.Unlock()
	switch {
	case isGrant:
		writeJSON(w, http.StatusOK, grantResponse(&g))
	case isSession:
		writeJSON(w, http.StatusOK, map[string]any{"active": s.active, "sub": s.subject})
	default:
		writeJSON(w, http.StatusOK, map[string]any{"active": false})
	}
}

func grantResponse(g *Grant) map[string]any {
	resp := map[string]any{
		"active":        true,
		"token_type":    "DPoP",
		"sub":           g.Subject,
		"aud":           g.Audience,
		"exp":           g.Expires.Unix(),
		"cnf":           map[string]any{"jkt": g.JKT},
		"relay_target":  g.Target,
		"relay_session": g.Session,
	}
	for k, v := range g.Override {
		if v == nil {
			delete(resp, k)
		} else {
			resp[k] = v
		}
	}
	return resp
}

func (a *AS) authenticate(form map[string][]string) error {
	if first(form, "client_assertion_type") != jwtBearer {
		return errors.New("client_assertion_type must be jwt-bearer")
	}
	jws, err := jose.ParseSignedCompact(first(form, "client_assertion"), algorithms)
	if err != nil {
		return err
	}
	var claims map[string]any
	if err := json.Unmarshal(jws.UnsafePayloadWithoutVerification(), &claims); err != nil {
		return err
	}
	iss, _ := claims["iss"].(string)
	a.mu.Lock()
	key := a.clients[iss]
	a.mu.Unlock()
	if key == nil {
		return errors.New("unknown client")
	}
	if _, err := jws.Verify(key); err != nil {
		return err
	}
	now := float64(time.Now().Unix())
	exp, _ := claims["exp"].(float64)
	iat, _ := claims["iat"].(float64)
	jti, _ := claims["jti"].(string)
	switch {
	case claims["sub"] != iss:
		return errors.New("sub must equal iss")
	case claims["aud"] != a.issuer:
		return errors.New("aud must be the issuer")
	case exp <= now || exp-iat > 60:
		return errors.New("assertion expired or too long-lived")
	case jti == "":
		return errors.New("jti required")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.seenAssertions[jti] {
		return errors.New("assertion replayed")
	}
	a.seenAssertions[jti] = true
	a.assertions = append(a.assertions, claims)
	a.assertionKIDs = append(a.assertionKIDs, jws.Signatures[0].Header.KeyID)
	return nil
}

func (a *AS) register(w http.ResponseWriter, r *http.Request) {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	a.mu.Lock()
	valid := ok && a.initialTokens[tok]
	delete(a.initialTokens, tok)
	a.mu.Unlock()
	if !valid {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_token"})
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_client_metadata"})
		return
	}
	raw, err := json.Marshal(body["jwks"])
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_client_metadata"})
		return
	}
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(raw, &set); err != nil || len(set.Keys) != 1 || !set.Keys[0].IsPublic() ||
		body["token_endpoint_auth_method"] != "private_key_jwt" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_client_metadata"})
		return
	}
	id := rand.Text()
	a.mu.Lock()
	a.clients[id] = &set.Keys[0]
	a.registrations = append(a.registrations, body)
	a.mu.Unlock()
	resp := maps.Clone(body)
	resp["client_id"] = id
	resp["client_id_issued_at"] = time.Now().Unix()
	writeJSON(w, http.StatusCreated, resp)
}

func first(form map[string][]string, key string) string {
	if v := form[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		panic(err)
	}
}
