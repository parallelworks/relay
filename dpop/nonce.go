package dpop

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

const (
	nonceKeySize  = 32
	nonceTimeSize = 8
	nonceSize     = nonceTimeSize + sha256.Size
	nonceSkew     = 5 * time.Second
)

// Nonces issues and checks stateless server nonces (RFC 9449 §8). Replicas that share a key accept
// each other's nonces.
type Nonces struct {
	key      []byte
	lifetime time.Duration
}

// NewNonces returns a nonce source keyed by key, which must be at least 32 bytes.
func NewNonces(key []byte, lifetime time.Duration) (*Nonces, error) {
	if len(key) < nonceKeySize {
		return nil, errors.New("dpop: nonce key must be at least 32 bytes")
	}
	if lifetime <= 0 {
		return nil, errors.New("dpop: nonce lifetime must be positive")
	}
	return &Nonces{key: append([]byte(nil), key...), lifetime: lifetime}, nil
}

// NewRandomNonces returns a nonce source with a fresh random key.
func NewRandomNonces(lifetime time.Duration) (*Nonces, error) {
	key := make([]byte, nonceKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return NewNonces(key, lifetime)
}

// Issue returns a new nonce.
func (n *Nonces) Issue() string {
	var buf [nonceSize]byte
	binary.BigEndian.PutUint64(buf[:nonceTimeSize], uint64(time.Now().Unix())) //nolint:gosec // Unix time after 1970 is non-negative.
	copy(buf[nonceTimeSize:], n.mac(buf[:nonceTimeSize]))
	return base64.RawURLEncoding.EncodeToString(buf[:])
}

func (n *Nonces) mac(b []byte) []byte {
	m := hmac.New(sha256.New, n.key)
	m.Write(b)
	return m.Sum(nil)
}

func (n *Nonces) valid(s string) bool {
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil || len(raw) != nonceSize {
		return false
	}
	if !hmac.Equal(raw[nonceTimeSize:], n.mac(raw[:nonceTimeSize])) {
		return false
	}
	issued := time.Unix(int64(binary.BigEndian.Uint64(raw[:nonceTimeSize])), 0) //nolint:gosec // Authenticated by the MAC above.
	now := time.Now()
	return !issued.After(now.Add(nonceSkew)) && now.Sub(issued) <= n.lifetime
}
