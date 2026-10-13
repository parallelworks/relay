package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"math/big"
	"os"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

const (
	testToken  = "access-token"
	testTarget = "10.4.2.17:41823"
)

var testURI = TargetURI(testTarget)

type fixture struct {
	t   *testing.T
	key crypto.Signer
	alg string
	jwk map[string]any
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return fixtureFor(t, k, "ES256")
}

func fixtureFor(t *testing.T, key crypto.Signer, alg string) *fixture {
	t.Helper()
	return &fixture{t: t, key: key, alg: alg, jwk: publicJWK(t, key.Public())}
}

func publicJWK(t *testing.T, key any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(jose.JSONWebKey{Key: key})
	if err != nil {
		t.Fatal(err)
	}
	var jwk map[string]any
	if err := json.Unmarshal(raw, &jwk); err != nil {
		t.Fatal(err)
	}
	return jwk
}

func (f *fixture) header() map[string]any {
	return map[string]any{"typ": "dpop+jwt", "alg": f.alg, "jwk": f.jwk}
}

func (f *fixture) claims() map[string]any {
	return map[string]any{
		"jti": rand.Text(),
		"htm": "CONNECT",
		"htu": testURI,
		"iat": time.Now().Unix(),
		"ath": TokenHash(testToken),
	}
}

func (f *fixture) sign(header, claims any) string {
	f.t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		f.t.Fatal(err)
	}
	var p []byte
	if s, ok := claims.(string); ok {
		p = []byte(s)
	} else if p, err = json.Marshal(claims); err != nil {
		f.t.Fatal(err)
	}
	input := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(p)
	return input + "." + base64.RawURLEncoding.EncodeToString(f.signature(input))
}

func (f *fixture) signature(input string) []byte {
	f.t.Helper()
	switch k := f.key.(type) {
	case *ecdsa.PrivateKey:
		size := (k.Curve.Params().BitSize + 7) / 8
		var digest []byte
		if size == 32 {
			d := sha256.Sum256([]byte(input))
			digest = d[:]
		} else {
			d := sha512.Sum384([]byte(input))
			digest = d[:]
		}
		r, s, err := ecdsa.Sign(rand.Reader, k, digest)
		if err != nil {
			f.t.Fatal(err)
		}
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		return out
	case *rsa.PrivateKey:
		d := sha256.Sum256([]byte(input))
		sig, err := rsa.SignPSS(rand.Reader, k, crypto.SHA256, d[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		if err != nil {
			f.t.Fatal(err)
		}
		return sig
	default:
		f.t.Fatalf("unsupported key %T", k)
		return nil
	}
}

func (f *fixture) proof() string {
	return f.sign(f.header(), f.claims())
}

func (f *fixture) jkt() string {
	return thumbprint(&jose.JSONWebKey{Key: f.key.Public()})
}

func request(proof string) Request {
	return Request{Method: "CONNECT", URI: testURI, AccessToken: testToken, Proof: proof}
}

func expectErr(t *testing.T, v *Verifier, proof string, want error) {
	t.Helper()
	if _, err := v.Verify(request(proof)); !errors.Is(err, want) {
		t.Fatalf("Verify err = %v, want %v", err, want)
	}
}

func TestVerifyAcceptsValidProofs(t *testing.T) {
	t.Parallel()
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []*fixture{newFixture(t), fixtureFor(t, p384, "ES384"), fixtureFor(t, rsaKey, "PS256")} {
		v := NewVerifier(Options{})
		got, err := v.Verify(request(f.proof()))
		if err != nil {
			t.Fatalf("%s: %v", f.alg, err)
		}
		if err := got.Bound(f.jkt()); err != nil {
			t.Fatalf("%s: %v", f.alg, err)
		}
	}
}

func TestVerifyAcceptsEquivalentURIs(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := NewVerifier(Options{})
	cases := []struct{ htu, uri string }{
		{"HTTPS://10.4.2.17:41823", "https://10.4.2.17:41823"},
		{"https://10.4.2.17:41823/", "https://10.4.2.17:41823"},
		{"https://example.com:443/a%2fb", "https://EXAMPLE.com/a%2Fb"},
		{"http://example.com:80/x", "http://example.com/x"},
		{"https://[2001:DB8::1]:22", "https://[2001:db8::1]:22"},
		{"https://example.com/p?q=1#f", "https://example.com/p"},
	}
	for _, c := range cases {
		claims := f.claims()
		claims["htu"] = c.htu
		r := request(f.sign(f.header(), claims))
		r.URI = c.uri
		if _, err := v.Verify(r); err != nil {
			t.Errorf("htu %q against %q: %v", c.htu, c.uri, err)
		}
	}
}

func TestVerifyRejectsWrongType(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := NewVerifier(Options{})
	for _, typ := range []any{"jwt", "at+jwt", "", nil} {
		h := f.header()
		if typ == nil {
			delete(h, "typ")
		} else {
			h["typ"] = typ
		}
		expectErr(t, v, f.sign(h, f.claims()), ErrType)
	}
	h := f.header()
	h["typ"] = "DPoP+JWT"
	if _, err := v.Verify(request(f.sign(h, f.claims()))); err != nil {
		t.Fatalf("typ compares case-insensitively (RFC 7515 §4.1.9): %v", err)
	}
}

func TestVerifyRejectsDisallowedAlgorithm(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := NewVerifier(Options{})
	for _, alg := range []string{"none", "HS256", "RS256", "ES512", "EdDSA", ""} {
		h := f.header()
		h["alg"] = alg
		expectErr(t, v, f.sign(h, f.claims()), ErrAlgorithm)
	}
	unsigned := strings.Join([]string{
		base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"dpop+jwt","alg":"none","jwk":{}}`)),
		base64.RawURLEncoding.EncodeToString([]byte(`{}`)), "",
	}, ".")
	expectErr(t, v, unsigned, ErrAlgorithm)
}

func TestVerifyRejectsPrivateKey(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := NewVerifier(Options{})
	raw, err := json.Marshal(jose.JSONWebKey{Key: f.key})
	if err != nil {
		t.Fatal(err)
	}
	var private map[string]any
	if err := json.Unmarshal(raw, &private); err != nil {
		t.Fatal(err)
	}
	h := f.header()
	h["jwk"] = private
	expectErr(t, v, f.sign(h, f.claims()), ErrKey)
	for _, member := range []string{"x5c", "x5t", "x5t#S256", "x5u", "k", "d", "oth"} {
		jwk := maps.Clone(f.jwk)
		jwk[member] = "AAAA"
		h := f.header()
		h["jwk"] = jwk
		expectErr(t, v, f.sign(h, f.claims()), ErrKey)
	}
}

func TestVerifyRejectsUnusableKeys(t *testing.T) {
	t.Parallel()
	v := NewVerifier(Options{})
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expectErr(t, v, fixtureFor(t, p384, "ES256").proof(), ErrKey)
	p256 := newFixture(t)
	h := p256.header()
	h["alg"] = "ES384"
	expectErr(t, v, p256.sign(h, p256.claims()), ErrKey)
	h["alg"] = "PS256"
	expectErr(t, v, p256.sign(h, p256.claims()), ErrKey)

	small := &rsa.PublicKey{N: new(big.Int).SetBit(big.NewInt(1), 1023, 1), E: 65537}
	h = p256.header()
	h["alg"] = "PS256"
	h["jwk"] = publicJWK(t, small)
	expectErr(t, v, p256.sign(h, p256.claims()), ErrKey)

	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h = p256.header()
	h["jwk"] = publicJWK(t, edPub)
	expectErr(t, v, p256.sign(h, p256.claims()), ErrKey)

	h = p256.header()
	h["jwk"] = map[string]any{"kty": "EC", "crv": "P-256", "x": "AA", "y": "AA"}
	expectErr(t, v, p256.sign(h, p256.claims()), ErrKey)
	h["jwk"] = "not an object"
	expectErr(t, v, p256.sign(h, p256.claims()), ErrKey)
}

func TestVerifyRejectsBadSignature(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	other := newFixture(t)
	v := NewVerifier(Options{})
	h := f.header()
	h["jwk"] = other.jwk
	expectErr(t, v, f.sign(h, f.claims()), ErrSignature)

	proof := f.proof()
	i := strings.LastIndexByte(proof, '.')
	sig, err := base64.RawURLEncoding.DecodeString(proof[i+1:])
	if err != nil {
		t.Fatal(err)
	}
	sig[0] ^= 0xff
	expectErr(t, v, proof[:i+1]+base64.RawURLEncoding.EncodeToString(sig), ErrSignature)
}

func TestVerifyRejectsMalformedProofs(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := NewVerifier(Options{})
	valid := f.proof()
	for name, proof := range map[string]string{
		"too large":         strings.Repeat("a", MaxProofSize+1),
		"no dots":           "abc",
		"bad header base64": "!!!.e30.e30",
		"header not json":   base64.RawURLEncoding.EncodeToString([]byte("x")) + ".e30.e30",
		"crit":              f.sign(withMember(f.header(), "crit", []string{"exp"}), f.claims()),
		"no jwk":            f.sign(withoutMember(f.header(), "jwk"), f.claims()),
		"four parts":        valid + ".x",
		"bad signature b64": valid[:strings.LastIndexByte(valid, '.')+1] + "!!!",
		"claims not json":   f.sign(f.header(), "not json"),
		"trailing claims":   f.sign(f.header(), `{"jti":"a","htm":"CONNECT","htu":"https://a","iat":1,"ath":"x"}{}`),
	} {
		if _, err := v.Verify(request(proof)); !errors.Is(err, ErrMalformed) {
			t.Errorf("%s: err = %v, want ErrMalformed", name, err)
		}
	}
	for _, missing := range []string{"jti", "htm", "htu", "iat", "ath"} {
		expectErr(t, v, f.sign(f.header(), withoutMember(f.claims(), missing)), ErrMalformed)
	}
	expectErr(t, v, f.sign(f.header(), withMember(f.claims(), "jti", strings.Repeat("j", maxIDSize+1))), ErrMalformed)
	expectErr(t, v, f.sign(f.header(), withMember(f.claims(), "iat", 1.5)), ErrMalformed)
	expectErr(t, v, f.sign(f.header(), withMember(f.claims(), "iat", "now")), ErrMalformed)
	expectErr(t, v, f.sign(f.header(), withMember(f.claims(), "htm", 7)), ErrMalformed)
}

func TestVerifyRejectsMethodMismatch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := NewVerifier(Options{})
	for _, m := range []string{"GET", "connect", "POST"} {
		expectErr(t, v, f.sign(f.header(), withMember(f.claims(), "htm", m)), ErrMethod)
	}
}

func TestVerifyRejectsURIMismatch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := NewVerifier(Options{})
	for _, htu := range []string{
		"https://10.4.2.17:41824", "https://10.4.2.18:41823", "http://10.4.2.17:41823",
		"https://10.4.2.17:41823/other", "ftp://10.4.2.17:41823", "https://user@10.4.2.17:41823",
		"https:opaque", "/relative", "https://[::1", "%zz", "https://:", "https://:41823",
	} {
		expectErr(t, v, f.sign(f.header(), withMember(f.claims(), "htu", htu)), ErrURI)
	}
	r := request(f.proof())
	r.URI = "%zz"
	if _, err := v.Verify(r); !errors.Is(err, ErrURI) {
		t.Fatalf("unparseable request URI: %v", err)
	}
}

func TestVerifyRejectsStaleIssuedAt(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		v := NewVerifier(Options{Window: 30 * time.Second})
		now := time.Now().Unix()
		for _, iat := range []int64{now - 31, now + 31, 0} {
			expectErr(t, v, f.sign(f.header(), withMember(f.claims(), "iat", iat)), ErrIssuedAt)
		}
		for _, iat := range []int64{now - 30, now + 30} {
			if _, err := v.Verify(request(f.sign(f.header(), withMember(f.claims(), "iat", iat)))); err != nil {
				t.Fatalf("iat at the window edge rejected: %v", err)
			}
		}
		proof := f.proof()
		time.Sleep(31 * time.Second)
		expectErr(t, v, proof, ErrIssuedAt)
	})
}

func TestVerifyRejectsReplayedID(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		f := newFixture(t)
		v := NewVerifier(Options{Window: 10 * time.Second})
		proof := f.proof()
		if _, err := v.Verify(request(proof)); err != nil {
			t.Fatal(err)
		}
		expectErr(t, v, proof, ErrReplay)

		claims := f.claims()
		claims["iat"] = time.Now().Add(10 * time.Second).Unix()
		future := f.sign(f.header(), claims)
		if _, err := v.Verify(request(future)); err != nil {
			t.Fatal(err)
		}
		for range 3 {
			time.Sleep(6 * time.Second)
			expectErr(t, v, future, ErrReplay)
		}
	})
}

func TestReplayCacheGenerations(t *testing.T) {
	t.Parallel()
	start := time.Unix(1_000_000, 0)
	c := replayCache{generation: 10 * time.Second, max: 2}
	if err := c.add("a", start); err != nil {
		t.Fatal(err)
	}
	if err := c.add("b", start.Add(11*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := c.add("a", start.Add(12*time.Second)); !errors.Is(err, ErrReplay) {
		t.Fatalf("jti from the previous generation: %v", err)
	}
	if err := c.add("a", start.Add(25*time.Second)); err != nil {
		t.Fatalf("jti two generations old should be forgotten: %v", err)
	}
	if err := c.add("c", start.Add(25*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := c.add("d", start.Add(25*time.Second)); !errors.Is(err, ErrReplayCacheFull) {
		t.Fatalf("full cache: %v", err)
	}
	if err := c.add("e", start.Add(100*time.Second)); err != nil {
		t.Fatalf("idle cache should reset: %v", err)
	}
}

func TestVerifyReportsFullReplayCache(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := NewVerifier(Options{MaxReplayEntries: 1})
	if _, err := v.Verify(request(f.proof())); err != nil {
		t.Fatal(err)
	}
	expectErr(t, v, f.proof(), ErrReplayCacheFull)
}

func TestVerifyRejectsTokenHashMismatch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := NewVerifier(Options{})
	expectErr(t, v, f.sign(f.header(), withMember(f.claims(), "ath", TokenHash("other"))), ErrTokenHash)
	r := request(f.proof())
	r.AccessToken = "other"
	if _, err := v.Verify(r); !errors.Is(err, ErrTokenHash) {
		t.Fatalf("proof for another token: %v", err)
	}
}

func TestVerifyRejectsThumbprintMismatch(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	got, err := NewVerifier(Options{}).Verify(request(f.proof()))
	if err != nil {
		t.Fatal(err)
	}
	if err := got.Bound(newFixture(t).jkt()); !errors.Is(err, ErrThumbprint) {
		t.Fatalf("other key's thumbprint: %v", err)
	}
	if err := got.Bound(""); !errors.Is(err, ErrThumbprint) {
		t.Fatalf("empty thumbprint: %v", err)
	}
}

func TestVerifyRejectsMissingNonce(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		nonces, err := NewRandomNonces(time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		other, err := NewRandomNonces(time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		f := newFixture(t)
		v := NewVerifier(Options{Nonces: nonces})
		expectErr(t, v, f.proof(), ErrNonce)
		expectErr(t, v, f.sign(f.header(), withMember(f.claims(), "nonce", other.Issue())), ErrNonce)
		expectErr(t, v, f.sign(f.header(), withMember(f.claims(), "nonce", "!!")), ErrNonce)
		expectErr(t, v, f.sign(f.header(), withMember(f.claims(), "nonce", "AAAA")), ErrNonce)

		good := nonces.Issue()
		if _, err := v.Verify(request(f.sign(f.header(), withMember(f.claims(), "nonce", good)))); err != nil {
			t.Fatalf("fresh nonce rejected: %v", err)
		}
		time.Sleep(61 * time.Second)
		expectErr(t, v, f.sign(f.header(), withMember(f.claims(), "nonce", good)), ErrNonce)
	})
}

func TestNonceRejectsFutureIssue(t *testing.T) {
	t.Parallel()
	n, err := NewNonces(make([]byte, 32), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	var future string
	synctest.Test(t, func(*testing.T) {
		time.Sleep(time.Hour)
		future = n.Issue()
	})
	synctest.Test(t, func(t *testing.T) {
		if n.valid(future) {
			t.Fatal("nonce issued an hour ahead accepted")
		}
	})
}

func TestNewNonces(t *testing.T) {
	t.Parallel()
	if _, err := NewNonces(make([]byte, 31), time.Minute); err == nil {
		t.Error("short key accepted")
	}
	if _, err := NewNonces(make([]byte, 32), 0); err == nil {
		t.Error("zero lifetime accepted")
	}
	key := make([]byte, 32)
	n, err := NewNonces(key, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	key[0] = 1
	if !n.valid(n.Issue()) {
		t.Fatal("nonce key must not alias the caller's slice")
	}
}

func TestSecretComparisonsUseConstantTime(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	constantTime := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch pkg.Name + "." + sel.Sel.Name {
			case "hmac.Equal", "subtle.ConstantTimeCompare":
				constantTime++
			case "bytes.Equal", "bytes.Compare", "reflect.DeepEqual", "slices.Equal":
				t.Errorf("%s: %s.%s compares bytes in variable time", fset.Position(call.Pos()), pkg.Name, sel.Sel.Name)
			}
			return true
		})
	}
	if constantTime == 0 {
		t.Fatal("nonce MACs are not compared with hmac.Equal or subtle.ConstantTimeCompare")
	}
}

func TestProverRoundTrip(t *testing.T) {
	t.Parallel()
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p256, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	nonces, err := NewRandomNonces(time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(Options{Nonces: nonces})
	for _, key := range []crypto.Signer{p256, p384, rsaKey} {
		p, err := NewProver(key)
		if err != nil {
			t.Fatal(err)
		}
		proof, err := p.Proof("CONNECT", testURI+"?q=1#f", testToken, nonces.Issue())
		if err != nil {
			t.Fatal(err)
		}
		got, err := v.Verify(request(proof))
		if err != nil {
			t.Fatalf("%T: %v", key, err)
		}
		if err := got.Bound(p.Thumbprint()); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNewProverRejectsUnsupportedKeys(t *testing.T) {
	t.Parallel()
	p521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	huge := new(rsa.PrivateKey)
	huge.N, huge.E = new(big.Int).Lsh(big.NewInt(1), 8192), 65537
	for _, key := range []crypto.Signer{p521, ed, huge} {
		if _, proverErr := NewProver(key); proverErr == nil {
			t.Errorf("%T accepted", key)
		}
	}
	p, err := NewProver(mustKey(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Proof("CONNECT", "%zz", testToken, ""); err == nil {
		t.Error("unparseable URI accepted")
	}
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestNewVerifierDefaults(t *testing.T) {
	t.Parallel()
	v := NewVerifier(Options{Window: -1, MaxReplayEntries: -1})
	if v.window != DefaultWindow || v.replay.max != DefaultMaxReplayEntries || v.replay.generation != 2*DefaultWindow {
		t.Fatalf("defaults not applied: %+v", v)
	}
}

func TestThumbprintPanicsOnUnsupportedKey(t *testing.T) {
	t.Parallel()
	defer func() {
		if recover() == nil {
			t.Fatal("thumbprint of an unsupported key did not panic")
		}
	}()
	thumbprint(&jose.JSONWebKey{Key: "not a key"})
}

func withMember(m map[string]any, k string, v any) map[string]any {
	m[k] = v
	return m
}

func withoutMember(m map[string]any, k string) map[string]any {
	delete(m, k)
	return m
}

func rsaPublicOfBits(bits int) *rsa.PublicKey {
	n := new(big.Int).SetBit(big.NewInt(1), bits-1, 1)
	return &rsa.PublicKey{N: n, E: 65537}
}

func TestVerifyRSAKeySizeBounds(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := NewVerifier(Options{})
	for bits, want := range map[int]error{2047: ErrKey, 2048: ErrSignature, 4096: ErrSignature, 4097: ErrKey} {
		h := f.header()
		h["alg"] = "PS256"
		h["jwk"] = publicJWK(t, rsaPublicOfBits(bits))
		if _, err := v.Verify(request(f.sign(h, f.claims()))); !errors.Is(err, want) {
			t.Errorf("%d-bit key: err = %v, want %v", bits, err, want)
		}
	}
}

func TestNewProverRSAKeySizeBounds(t *testing.T) {
	t.Parallel()
	for bits, ok := range map[int]bool{2047: false, 2048: true, 4096: true, 4097: false} {
		k := new(rsa.PrivateKey)
		k.PublicKey = *rsaPublicOfBits(bits)
		if _, err := NewProver(k); (err == nil) != ok {
			t.Errorf("%d-bit key: err = %v, want accepted = %v", bits, err, ok)
		}
	}
}

func TestVerifyAcceptsLongestID(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	if _, err := NewVerifier(Options{}).Verify(request(f.sign(f.header(), withMember(f.claims(), "jti", strings.Repeat("j", maxIDSize))))); err != nil {
		t.Fatalf("jti of exactly %d bytes rejected: %v", maxIDSize, err)
	}
}

func TestVerifyAcceptsProofAtSizeLimit(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := NewVerifier(Options{})
	for headerPad := range 4 {
		for pad := MaxProofSize; pad > 0; pad-- {
			h := withMember(f.header(), "kid", strings.Repeat("k", headerPad))
			proof := f.sign(h, withMember(f.claims(), "pad", strings.Repeat("p", pad)))
			if len(proof) > MaxProofSize {
				continue
			}
			if len(proof) < MaxProofSize {
				break
			}
			if _, err := v.Verify(request(proof)); err != nil {
				t.Fatalf("proof of exactly %d bytes rejected: %v", MaxProofSize, err)
			}
			return
		}
	}
	t.Fatalf("could not build a proof of exactly %d bytes", MaxProofSize)
}

func TestNonceLifetimeBoundary(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		n, err := NewNonces(make([]byte, 32), time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		nonce := n.Issue()
		time.Sleep(time.Minute)
		if !n.valid(nonce) {
			t.Fatal("nonce rejected at exactly its lifetime")
		}
		time.Sleep(time.Second)
		if n.valid(nonce) {
			t.Fatal("nonce accepted after its lifetime")
		}
	})
}

func TestReplayCacheRotatesAtExactBoundaries(t *testing.T) {
	t.Parallel()
	start := time.Unix(1_000_000, 0)
	gen := 10 * time.Second

	c := replayCache{generation: gen, max: 1}
	if err := c.add("a", start); err != nil {
		t.Fatal(err)
	}
	if err := c.add("b", start.Add(gen)); err != nil {
		t.Fatalf("a full generation should rotate exactly at its length: %v", err)
	}

	c = replayCache{generation: gen, max: 1}
	if err := c.add("a", start); err != nil {
		t.Fatal(err)
	}
	if err := c.add("a", start.Add(2*gen)); err != nil {
		t.Fatalf("an entry should be forgotten exactly two generations later: %v", err)
	}
}
