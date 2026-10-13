// Package registration registers the relay as an OAuth 2.0 client with Dynamic Client Registration
// (RFC 7591) and stores its credentials.
package registration

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"os"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/parallelworks/relay/dpop"
	"github.com/parallelworks/relay/introspect"
)

const (
	// DefaultKeyName is the default file name of the relay's private key.
	DefaultKeyName = "relay-key.pem"
	// DefaultClientName is the default file name of the relay's registration.
	DefaultClientName = "relay-client.json"
	// SoftwareID identifies this software in registration requests.
	SoftwareID   = "github.com/parallelworks/relay"
	pemBlockType = "PRIVATE KEY"
)

var (
	// ErrNotRegistered reports that no credentials are stored.
	ErrNotRegistered = errors.New("registration: relay is not registered")
	// ErrAlreadyRegistered reports that credentials are already stored.
	ErrAlreadyRegistered = errors.New("registration: relay is already registered")
	// ErrPermissiveKeyFile reports a key file others may read or write.
	ErrPermissiveKeyFile = errors.New("registration: key file must be 0600, or 0640 when owned by root")
	// ErrKeyFileOwner reports a key file owned by neither the relay's user nor root.
	ErrKeyFileOwner = errors.New("registration: key file must be owned by the relay's user or by root")
	// ErrIssuerMismatch reports stored credentials registered with a different issuer.
	ErrIssuerMismatch = errors.New("registration: stored credentials belong to another issuer")
)

// Options names the files a Store uses, relative to its directory.
type Options struct {
	KeyName    string
	ClientName string
}

// Store keeps the relay's credentials in one directory. Every file access goes through os.Root, so
// configured names cannot reach outside it.
type Store struct {
	root       *os.Root
	keyName    string
	clientName string
}

// Open returns a store rooted at dir.
func Open(dir string, opts Options) (*Store, error) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	if opts.KeyName == "" {
		opts.KeyName = DefaultKeyName
	}
	if opts.ClientName == "" {
		opts.ClientName = DefaultClientName
	}
	return &Store{root: root, keyName: opts.KeyName, clientName: opts.ClientName}, nil
}

// Close releases the store's directory.
func (s *Store) Close() error {
	return s.root.Close()
}

type record struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
	KeyID    string `json:"kid"`
}

// Load returns the stored credentials for issuer.
func (s *Store) Load(issuer string) (introspect.Credentials, error) {
	raw, err := s.root.ReadFile(s.clientName)
	if errors.Is(err, fs.ErrNotExist) {
		return introspect.Credentials{}, ErrNotRegistered
	}
	if err != nil {
		return introspect.Credentials{}, err
	}
	var rec record
	if err = json.Unmarshal(raw, &rec); err != nil || rec.ClientID == "" {
		return introspect.Credentials{}, fmt.Errorf("registration: %s is not a valid registration", s.clientName)
	}
	if rec.Issuer != issuer {
		return introspect.Credentials{}, ErrIssuerMismatch
	}
	key, err := s.loadKey()
	if err != nil {
		return introspect.Credentials{}, err
	}
	return introspect.Credentials{ClientID: rec.ClientID, KeyID: rec.KeyID, Key: key}, nil
}

// checkKeyFile applies PostgreSQL's rule for private key files: a key owned by the relay's user is
// 0600 or stricter; one owned by root may also be group-readable, 0640 or stricter, which is how
// Kubernetes mounts a Secret into a pod with an fsGroup.
func checkKeyFile(perm fs.FileMode, owner, euid int) error {
	switch owner {
	case 0:
		if perm&0o037 != 0 {
			return ErrPermissiveKeyFile
		}
	case euid:
		if perm&0o077 != 0 {
			return ErrPermissiveKeyFile
		}
	default:
		return ErrKeyFileOwner
	}
	return nil
}

func (s *Store) loadKey() (key crypto.Signer, err error) {
	f, err := s.root.Open(s.keyName)
	if err != nil {
		return nil, err
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			key, err = nil, cerr
		}
	}()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if kerr := checkKeyFile(info.Mode().Perm(), fileOwner(info), os.Geteuid()); kerr != nil {
		return nil, fmt.Errorf("%w: %s is %v", kerr, s.keyName, info.Mode().Perm())
	}
	raw, err := io.ReadAll(io.LimitReader(f, 64<<10))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(raw)
	if block == nil || block.Type != pemBlockType {
		return nil, fmt.Errorf("registration: %s is not a PEM %s", s.keyName, pemBlockType)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("registration: %s: %w", s.keyName, err)
	}
	switch k := parsed.(type) {
	case *ecdsa.PrivateKey:
		return k, nil
	case *rsa.PrivateKey:
		return k, nil
	default:
		return nil, fmt.Errorf("registration: %s holds an unsupported %T", s.keyName, parsed)
	}
}

func (s *Store) save(issuer string, creds introspect.Credentials) error {
	der, err := x509.MarshalPKCS8PrivateKey(creds.Key)
	if err != nil {
		return err
	}
	if werr := s.writeAtomic(s.keyName, pem.EncodeToMemory(&pem.Block{Type: pemBlockType, Bytes: der})); werr != nil {
		return werr
	}
	rec, err := json.Marshal(record{Issuer: issuer, ClientID: creds.ClientID, KeyID: creds.KeyID})
	if err != nil {
		return err
	}
	return s.writeAtomic(s.clientName, rec)
}

func (s *Store) writeAtomic(name string, data []byte) error {
	tmp := name + ".tmp-" + rand.Text()
	f, err := s.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if err := errors.Join(werr, serr, cerr); err != nil {
		return errors.Join(err, s.root.Remove(tmp))
	}
	return s.root.Rename(tmp, name)
}

// Request describes a registration.
type Request struct {
	// Endpoint is the authorization server's registration_endpoint.
	Endpoint string
	// Issuer is the authorization server's issuer identifier.
	Issuer string
	// InitialAccessToken authorizes the registration (RFC 7591 §3).
	InitialAccessToken string
	// ClientName is shown to the authorization server's administrators.
	ClientName string
	// SoftwareVersion is this relay's version.
	SoftwareVersion string
}

type registrationError struct {
	Error       string `json:"error"`
	Description string `json:"error_description"`
}

// Register generates a key pair, registers its public half, stores the credentials, and returns them.
// The private key never leaves the relay.
func (s *Store) Register(ctx context.Context, client *http.Client, r *Request) (introspect.Credentials, error) {
	if _, err := s.root.Stat(s.clientName); err == nil {
		return introspect.Credentials{}, ErrAlreadyRegistered
	}
	key, err := dpop.GenerateKey()
	if err != nil {
		return introspect.Credentials{}, err
	}
	prover, err := dpop.NewProver(key)
	if err != nil {
		return introspect.Credentials{}, err
	}
	kid := prover.Thumbprint()
	pub := jose.JSONWebKey{Key: &key.PublicKey, KeyID: kid, Algorithm: string(jose.ES256), Use: "sig"}
	body, err := json.Marshal(map[string]any{ //nolint:gosec // G101: registration metadata member names, not credentials.
		"token_endpoint_auth_method":      "private_key_jwt",
		"token_endpoint_auth_signing_alg": string(jose.ES256),
		"jwks":                            jose.JSONWebKeySet{Keys: []jose.JSONWebKey{pub}},
		"grant_types":                     []string{},
		"response_types":                  []string{},
		"client_name":                     r.ClientName,
		"software_id":                     SoftwareID,
		"software_version":                r.SoftwareVersion,
	})
	if err != nil {
		return introspect.Credentials{}, err
	}
	status, raw, err := post(ctx, client, r, body)
	if err != nil {
		return introspect.Credentials{}, err
	}
	if status != http.StatusCreated {
		var e registrationError
		if err := json.Unmarshal(raw, &e); err != nil || e.Error == "" {
			return introspect.Credentials{}, fmt.Errorf("registration: status %d", status)
		}
		return introspect.Credentials{}, fmt.Errorf("registration: %s: %s", e.Error, e.Description)
	}
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.ClientID == "" {
		return introspect.Credentials{}, errors.New("registration: response has no client_id")
	}
	creds := introspect.Credentials{ClientID: out.ClientID, KeyID: kid, Key: key}
	if err := s.save(r.Issuer, creds); err != nil {
		return introspect.Credentials{}, err
	}
	return creds, nil
}

func post(ctx context.Context, client *http.Client, r *Request, body []byte) (status int, raw []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.Endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.InitialAccessToken)
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			status, raw, err = 0, nil, cerr
		}
	}()
	raw, err = io.ReadAll(io.LimitReader(resp.Body, introspect.MaxResponseSize+1))
	if err != nil {
		return 0, nil, err
	}
	if len(raw) > introspect.MaxResponseSize {
		return 0, nil, errors.New("registration: response too large")
	}
	if mt, _, perr := mime.ParseMediaType(resp.Header.Get("Content-Type")); perr != nil || mt != "application/json" {
		return 0, nil, fmt.Errorf("registration: status %d with content type %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	return resp.StatusCode, raw, nil
}
