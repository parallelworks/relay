package dpop

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	// MaxProofSize bounds the proof a verifier will parse.
	MaxProofSize = 4096
	maxIDSize    = 256
	minRSABits   = 2048
	maxRSABits   = 4096

	// DefaultWindow is the default iat acceptance window.
	DefaultWindow = 60 * time.Second
	// DefaultMaxReplayEntries bounds the remembered jti values per generation.
	DefaultMaxReplayEntries = 1 << 20
)

var publicJWKMembers = map[string]bool{
	"kty": true, "crv": true, "x": true, "y": true, "n": true, "e": true,
	"alg": true, "use": true, "kid": true, "key_ops": true,
}

// Options configures a Verifier. The zero value uses the defaults.
type Options struct {
	Window           time.Duration
	MaxReplayEntries int
	Nonces           *Nonces
}

// Verifier checks proofs against RFC 9449 §4.3 and remembers their jti values.
type Verifier struct {
	window time.Duration
	nonces *Nonces
	replay replayCache
}

// NewVerifier returns a verifier with opts.
func NewVerifier(opts Options) *Verifier {
	if opts.Window <= 0 {
		opts.Window = DefaultWindow
	}
	if opts.MaxReplayEntries <= 0 {
		opts.MaxReplayEntries = DefaultMaxReplayEntries
	}
	return &Verifier{
		window: opts.Window,
		nonces: opts.Nonces,
		replay: replayCache{generation: 2 * opts.Window, max: opts.MaxReplayEntries},
	}
}

// Request is what a proof is checked against.
type Request struct {
	Method      string
	URI         string
	AccessToken string
	Proof       string
}

// Verified is a proof that passed every check that does not need the token's introspection.
type Verified struct {
	JKT string
}

// Bound reports whether the proof's key is the one a token is bound to, given the token's cnf.jkt.
func (v Verified) Bound(jkt string) error {
	if jkt == "" || v.JKT != jkt {
		return ErrThumbprint
	}
	return nil
}

type claims struct {
	JTI   string      `json:"jti"`
	HTM   string      `json:"htm"`
	HTU   string      `json:"htu"`
	IAT   json.Number `json:"iat"`
	ATH   string      `json:"ath"`
	Nonce *string     `json:"nonce"`
}

// Verify checks r.Proof for r and records its jti. It does not check the token binding; call
// Verified.Bound with the token's cnf.jkt once the token has been introspected.
func (v *Verifier) Verify(r Request) (Verified, error) {
	if len(r.Proof) > MaxProofSize {
		return Verified{}, ErrMalformed
	}
	key, err := checkHeader(r.Proof)
	if err != nil {
		return Verified{}, err
	}
	jws, err := jose.ParseSignedCompact(r.Proof, Algorithms)
	if err != nil {
		return Verified{}, fmt.Errorf("%w: %w", ErrMalformed, err)
	}
	payload, err := jws.Verify(key)
	if err != nil {
		return Verified{}, ErrSignature
	}
	c, err := decodeClaims(payload)
	if err != nil {
		return Verified{}, err
	}
	if c.HTM != r.Method {
		return Verified{}, ErrMethod
	}
	if !sameURI(c.HTU, r.URI) {
		return Verified{}, ErrURI
	}
	iat, err := c.IAT.Int64()
	if err != nil {
		return Verified{}, ErrMalformed
	}
	now := time.Now()
	issued := time.Unix(iat, 0)
	if issued.Before(now.Add(-v.window)) || issued.After(now.Add(v.window)) {
		return Verified{}, ErrIssuedAt
	}
	if c.ATH != TokenHash(r.AccessToken) {
		return Verified{}, ErrTokenHash
	}
	if v.nonces != nil && (c.Nonce == nil || !v.nonces.valid(*c.Nonce)) {
		return Verified{}, ErrNonce
	}
	if err := v.replay.add(c.JTI, now); err != nil {
		return Verified{}, err
	}
	return Verified{JKT: thumbprint(key)}, nil
}

func checkHeader(proof string) (*jose.JSONWebKey, error) {
	encoded, _, ok := strings.Cut(proof, ".")
	if !ok {
		return nil, ErrMalformed
	}
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return nil, ErrMalformed
	}
	var h struct {
		Typ  *string         `json:"typ"`
		Alg  string          `json:"alg"`
		Crit json.RawMessage `json:"crit"`
		JWK  json.RawMessage `json:"jwk"`
	}
	if err := json.Unmarshal(raw, &h); err != nil {
		return nil, ErrMalformed
	}
	if h.Typ == nil || !strings.EqualFold(*h.Typ, proofType) {
		return nil, ErrType
	}
	alg := jose.SignatureAlgorithm(h.Alg)
	if !allowed(alg) {
		return nil, ErrAlgorithm
	}
	if h.Crit != nil || h.JWK == nil {
		return nil, ErrMalformed
	}
	var members map[string]json.RawMessage
	if err := json.Unmarshal(h.JWK, &members); err != nil {
		return nil, ErrKey
	}
	for member := range members {
		if !publicJWKMembers[member] {
			return nil, ErrKey
		}
	}
	var key jose.JSONWebKey
	if err := key.UnmarshalJSON(h.JWK); err != nil {
		return nil, ErrKey
	}
	if !key.IsPublic() || !keyMatches(alg, key.Key) {
		return nil, ErrKey
	}
	return &key, nil
}

func allowed(alg jose.SignatureAlgorithm) bool {
	return slices.Contains(Algorithms, alg)
}

func keyMatches(alg jose.SignatureAlgorithm, key any) bool {
	switch k := key.(type) {
	case *ecdsa.PublicKey:
		return (alg == jose.ES256 && k.Curve == elliptic.P256()) || (alg == jose.ES384 && k.Curve == elliptic.P384())
	case *rsa.PublicKey:
		bits := k.N.BitLen()
		return alg == jose.PS256 && bits >= minRSABits && bits <= maxRSABits
	default:
		return false
	}
}

func decodeClaims(payload []byte) (claims, error) {
	var c claims
	dec := json.NewDecoder(bytes.NewReader(payload))
	dec.UseNumber()
	if err := dec.Decode(&c); err != nil || dec.More() {
		return claims{}, ErrMalformed
	}
	if c.JTI == "" || len(c.JTI) > maxIDSize || c.HTM == "" || c.HTU == "" || c.IAT == "" || c.ATH == "" {
		return claims{}, ErrMalformed
	}
	return c, nil
}

func sameURI(a, b string) bool {
	na, okA := normalizeURI(a)
	nb, okB := normalizeURI(b)
	return okA && okB && na == nb
}

func normalizeURI(s string) (string, bool) {
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" || u.User != nil || u.Hostname() == "" {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "https" && scheme != "http" {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port != "" {
		authority += ":" + port
	}
	path := (&url.URL{Path: u.Path}).EscapedPath()
	if path == "" {
		path = "/"
	}
	return scheme + "://" + authority + path, true
}

type replayCache struct {
	mu         sync.Mutex
	generation time.Duration
	max        int
	started    time.Time
	current    map[string]struct{}
	previous   map[string]struct{}
}

func (c *replayCache) add(jti string, now time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch age := now.Sub(c.started); {
	case c.current == nil || age >= 2*c.generation:
		c.previous = nil
		c.current = map[string]struct{}{}
		c.started = now
	case age >= c.generation:
		c.previous = c.current
		c.current = map[string]struct{}{}
		c.started = c.started.Add(c.generation)
	}
	if _, ok := c.current[jti]; ok {
		return ErrReplay
	}
	if _, ok := c.previous[jti]; ok {
		return ErrReplay
	}
	if len(c.current) >= c.max {
		return ErrReplayCacheFull
	}
	c.current[jti] = struct{}{}
	return nil
}
