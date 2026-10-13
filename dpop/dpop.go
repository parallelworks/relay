// Package dpop creates and verifies OAuth 2.0 DPoP proofs (RFC 9449) for relay tunnel requests.
package dpop

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"errors"

	jose "github.com/go-jose/go-jose/v4"
)

// HeaderName is the HTTP field that carries a proof.
const HeaderName = "DPoP"

// NonceHeaderName is the HTTP field a server uses to supply a nonce (RFC 9449 §8).
const NonceHeaderName = "DPoP-Nonce"

// Scheme is the authorization scheme for DPoP-bound access tokens (RFC 9449 §7.1).
const Scheme = "DPoP"

const proofType = "dpop+jwt"

// Algorithms lists the signature algorithms accepted in proofs, in the order advertised to clients.
var Algorithms = []jose.SignatureAlgorithm{jose.ES256, jose.ES384, jose.PS256}

// Verification failures. Every failure except ErrNonce maps to the invalid_dpop_proof error code.
var (
	ErrMalformed       = errors.New("dpop: malformed proof")
	ErrType            = errors.New("dpop: wrong typ")
	ErrAlgorithm       = errors.New("dpop: algorithm not allowed")
	ErrKey             = errors.New("dpop: unacceptable key")
	ErrSignature       = errors.New("dpop: signature does not verify")
	ErrMethod          = errors.New("dpop: htm does not match the request method")
	ErrURI             = errors.New("dpop: htu does not match the request target")
	ErrIssuedAt        = errors.New("dpop: iat outside the acceptance window")
	ErrReplay          = errors.New("dpop: jti already used")
	ErrTokenHash       = errors.New("dpop: ath does not match the access token")
	ErrThumbprint      = errors.New("dpop: key is not the one the token is bound to")
	ErrNonce           = errors.New("dpop: nonce missing, unknown or expired")
	ErrReplayCacheFull = errors.New("dpop: replay cache full")
)

// TokenHash returns the ath value for an access token: base64url(SHA-256(token)).
func TokenHash(accessToken string) string {
	sum := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TargetURI returns the target URI of a CONNECT request for authority, used as htu.
func TargetURI(authority string) string {
	return "https://" + authority
}

func thumbprint(k *jose.JSONWebKey) string {
	b, err := k.Thumbprint(crypto.SHA256)
	if err != nil {
		panic("dpop: thumbprint of a validated key: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
