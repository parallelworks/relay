package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// Prover signs proofs with one key.
type Prover struct {
	signer jose.Signer
	jkt    string
}

// GenerateKey returns a new P-256 key for ES256 proofs.
func GenerateKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// NewProver returns a prover for key: an ECDSA P-256 or P-384 key, or an RSA key of 2048 to 4096 bits.
func NewProver(key crypto.Signer) (*Prover, error) {
	var alg jose.SignatureAlgorithm
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			alg = jose.ES256
		case elliptic.P384():
			alg = jose.ES384
		default:
			return nil, errors.New("dpop: unsupported curve")
		}
	case *rsa.PrivateKey:
		if bits := k.N.BitLen(); bits < minRSABits || bits > maxRSABits {
			return nil, errors.New("dpop: RSA key must be 2048 to 4096 bits")
		}
		alg = jose.PS256
	default:
		return nil, errors.New("dpop: unsupported key type")
	}
	opts := (&jose.SignerOptions{EmbedJWK: true}).WithType(proofType)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		return nil, err
	}
	return &Prover{signer: signer, jkt: thumbprint(&jose.JSONWebKey{Key: key.Public()})}, nil
}

// Thumbprint returns the RFC 7638 SHA-256 thumbprint of the prover's public key, the value a token
// bound to it carries as cnf.jkt.
func (p *Prover) Thumbprint() string {
	return p.jkt
}

// Proof returns a proof for a request with method to uri, presenting accessToken. nonce is the last
// nonce the server supplied, or empty.
func (p *Prover) Proof(method, uri, accessToken, nonce string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	u.RawQuery, u.Fragment, u.RawFragment = "", "", ""
	c := struct {
		JTI   string `json:"jti"`
		HTM   string `json:"htm"`
		HTU   string `json:"htu"`
		IAT   int64  `json:"iat"`
		ATH   string `json:"ath"`
		Nonce string `json:"nonce,omitempty"`
	}{
		JTI:   rand.Text(),
		HTM:   method,
		HTU:   u.String(),
		IAT:   time.Now().Unix(),
		ATH:   TokenHash(accessToken),
		Nonce: nonce,
	}
	payload, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	jws, err := p.signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}
