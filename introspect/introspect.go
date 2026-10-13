// Package introspect asks an OAuth 2.0 authorization server about relay tokens, using Token
// Introspection (RFC 7662), Authorization Server Metadata (RFC 8414) and private_key_jwt client
// authentication (RFC 7523).
package introspect

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/parallelworks/relay/policy"
)

const (
	// MaxResponseSize bounds every response body read from the authorization server.
	MaxResponseSize = 64 << 10
	// MaxSessionSize bounds relay_session.
	MaxSessionSize   = 512
	assertionLife    = 60 * time.Second
	requestTimeout   = 10 * time.Second
	idleConnTimeout  = 90 * time.Second
	metadataPath     = "/.well-known/oauth-authorization-server"
	jwtBearerType    = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" //nolint:gosec // G101: a registered URN, not a credential.
	formContentType  = "application/x-www-form-urlencoded"
	jsonContentType  = "application/json"
	dpopTokenType    = "DPoP"
	accessTokenHint  = "access_token"
	tokenParam       = "token"
	tokenTypeHintKey = "token_type_hint"
)

var (
	// ErrInactive reports a token the authorization server does not consider usable by this relay.
	ErrInactive = errors.New("introspect: token is not active for this relay")
	// ErrInvalidResponse reports a response that does not follow RFC 7662 or the relay protocol.
	ErrInvalidResponse = errors.New("introspect: invalid response")
	// ErrUnavailable reports a failure to get any answer from the authorization server.
	ErrUnavailable = errors.New("introspect: authorization server unavailable")
)

// NewHTTPClient returns a client that speaks only TLS 1.3, trusts roots when non-nil and the
// system pool otherwise, and never follows redirects.
func NewHTTPClient(roots *x509.CertPool) *http.Client {
	t := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
		TLSHandshakeTimeout: requestTimeout,
		MaxIdleConnsPerHost: 16,
		IdleConnTimeout:     idleConnTimeout,
		ForceAttemptHTTP2:   true,
	}
	return &http.Client{
		Transport: t,
		Timeout:   requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// Metadata is the subset of RFC 8414 metadata the relay uses.
type Metadata struct {
	Issuer                string `json:"issuer"`
	IntrospectionEndpoint string `json:"introspection_endpoint"`
	RegistrationEndpoint  string `json:"registration_endpoint"`
}

// MetadataURL returns the RFC 8414 §3 metadata location for issuer.
func MetadataURL(issuer string) (string, error) {
	u, err := url.Parse(issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || u.User != nil {
		return "", fmt.Errorf("introspect: issuer %q must be an https URL without query or fragment", issuer)
	}
	u.Path = metadataPath + strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	return u.String(), nil
}

// Discover fetches and validates the authorization server's metadata.
func Discover(ctx context.Context, client *http.Client, issuer string) (Metadata, error) {
	loc, err := MetadataURL(issuer)
	if err != nil {
		return Metadata{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, loc, http.NoBody)
	if err != nil {
		return Metadata{}, err
	}
	req.Header.Set("Accept", jsonContentType)
	body, err := do(client, req)
	if err != nil {
		return Metadata{}, err
	}
	var m Metadata
	if err := json.Unmarshal(body, &m); err != nil {
		return Metadata{}, fmt.Errorf("%w: metadata: %w", ErrInvalidResponse, err)
	}
	if m.Issuer != issuer {
		return Metadata{}, fmt.Errorf("%w: metadata issuer %q is not %q", ErrInvalidResponse, m.Issuer, issuer)
	}
	for name, endpoint := range map[string]string{
		"introspection_endpoint": m.IntrospectionEndpoint,
		"registration_endpoint":  m.RegistrationEndpoint,
	} {
		if endpoint == "" && name == "registration_endpoint" {
			continue
		}
		if u, err := url.Parse(endpoint); err != nil || u.Scheme != "https" || u.Host == "" {
			return Metadata{}, fmt.Errorf("%w: %s %q is not an https URL", ErrInvalidResponse, name, endpoint)
		}
	}
	return m, nil
}

// Credentials authenticate the relay to the authorization server.
type Credentials struct {
	ClientID string
	KeyID    string
	Key      crypto.Signer
}

// Client introspects tokens on behalf of one registered relay.
type Client struct {
	http     *http.Client
	meta     Metadata
	clientID string
	signer   jose.Signer
}

// NewClient returns a client for meta authenticating with creds.
func NewClient(meta Metadata, creds Credentials, httpClient *http.Client) (*Client, error) {
	if creds.ClientID == "" {
		return nil, errors.New("introspect: client_id is required")
	}
	alg, err := signingAlgorithm(creds.Key)
	if err != nil {
		return nil, err
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if creds.KeyID != "" {
		opts = opts.WithHeader("kid", creds.KeyID)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: creds.Key}, opts)
	if err != nil {
		return nil, err
	}
	return &Client{http: httpClient, meta: meta, clientID: creds.ClientID, signer: signer}, nil
}

// SigningAlgorithm returns the JWS algorithm the relay uses for key.
func SigningAlgorithm(key crypto.Signer) (string, error) {
	alg, err := signingAlgorithm(key)
	return string(alg), err
}

func signingAlgorithm(key crypto.Signer) (jose.SignatureAlgorithm, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		}
	case *rsa.PrivateKey:
		if k.N.BitLen() >= 2048 {
			return jose.PS256, nil
		}
	}
	return "", errors.New("introspect: key must be ECDSA P-256 or P-384, or RSA of at least 2048 bits")
}

// ClientID returns the relay's client identifier, which is also its audience.
func (c *Client) ClientID() string {
	return c.clientID
}

func (c *Client) assertion() (string, error) {
	now := time.Now()
	claims := map[string]any{
		"iss": c.clientID,
		"sub": c.clientID,
		"aud": c.meta.Issuer,
		"iat": now.Unix(),
		"exp": now.Add(assertionLife).Unix(),
		"jti": rand.Text(),
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	jws, err := c.signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return jws.CompactSerialize()
}

// Token is a validated introspection of a tunnel access token.
type Token struct {
	Subject string
	Expires time.Time
	JKT     string
	Target  netip.AddrPort
	Session string
}

// Session is a validated introspection of a relay_session token.
type Session struct {
	Active  bool
	Subject string
	Expires time.Time
}

type audience []string

func (a *audience) UnmarshalJSON(b []byte) error {
	var one string
	if err := json.Unmarshal(b, &one); err == nil {
		*a = audience{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return errors.New("aud must be a string or an array of strings")
	}
	*a = many
	return nil
}

type response struct {
	Active       *bool    `json:"active"`
	TokenType    *string  `json:"token_type"`
	Subject      string   `json:"sub"`
	Audience     audience `json:"aud"`
	Expires      *int64   `json:"exp"`
	Confirmation *struct {
		JKT string `json:"jkt"`
	} `json:"cnf"`
	RelayTarget  *string `json:"relay_target"`
	RelaySession *string `json:"relay_session"`
}

// AccessToken introspects a tunnel access token and validates the response against the relay
// protocol. Responses are never cached.
func (c *Client) AccessToken(ctx context.Context, token string) (Token, error) {
	r, err := c.introspect(ctx, url.Values{tokenParam: {token}, tokenTypeHintKey: {accessTokenHint}})
	if err != nil {
		return Token{}, err
	}
	return validateAccessToken(&r, c.clientID, time.Now())
}

func validateAccessToken(r *response, clientID string, now time.Time) (Token, error) {
	if !*r.Active {
		return Token{}, ErrInactive
	}
	if r.TokenType != nil && !strings.EqualFold(*r.TokenType, dpopTokenType) {
		return Token{}, fmt.Errorf("%w: token_type %q", ErrInactive, *r.TokenType)
	}
	if !slices.Contains(r.Audience, clientID) {
		return Token{}, fmt.Errorf("%w: audience does not include this relay", ErrInactive)
	}
	if r.Expires == nil || !time.Unix(*r.Expires, 0).After(now) {
		return Token{}, fmt.Errorf("%w: missing or past exp", ErrInactive)
	}
	if r.Confirmation == nil || r.Confirmation.JKT == "" {
		return Token{}, fmt.Errorf("%w: missing cnf.jkt", ErrInactive)
	}
	if r.RelayTarget == nil || r.RelaySession == nil || *r.RelaySession == "" || len(*r.RelaySession) > MaxSessionSize {
		return Token{}, fmt.Errorf("%w: missing or invalid relay members", ErrInactive)
	}
	target, err := policy.ParseTarget(*r.RelayTarget)
	if err != nil {
		return Token{}, fmt.Errorf("%w: relay_target: %w", ErrInactive, err)
	}
	return Token{
		Subject: r.Subject,
		Expires: time.Unix(*r.Expires, 0),
		JKT:     r.Confirmation.JKT,
		Target:  target,
		Session: *r.RelaySession,
	}, nil
}

// Session introspects a relay_session token. A valid answer is returned even when the session is
// inactive; an error means no valid answer was obtained.
func (c *Client) Session(ctx context.Context, session string) (Session, error) {
	r, err := c.introspect(ctx, url.Values{tokenParam: {session}})
	if err != nil {
		return Session{}, err
	}
	s := Session{Active: *r.Active, Subject: r.Subject}
	if r.Expires != nil {
		s.Expires = time.Unix(*r.Expires, 0)
	}
	return s, nil
}

func (c *Client) introspect(ctx context.Context, form url.Values) (response, error) {
	assertion, err := c.assertion()
	if err != nil {
		return response{}, err
	}
	form.Set("client_assertion_type", jwtBearerType)
	form.Set("client_assertion", assertion)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.meta.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return response{}, err
	}
	req.Header.Set("Content-Type", formContentType)
	req.Header.Set("Accept", jsonContentType)
	req.Header.Set("Cache-Control", "no-store")
	body, err := do(c.http, req)
	if err != nil {
		return response{}, err
	}
	return parseResponse(body)
}

func parseResponse(body []byte) (response, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	var r response
	if err := dec.Decode(&r); err != nil {
		return response{}, fmt.Errorf("%w: %w", ErrInvalidResponse, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return response{}, fmt.Errorf("%w: trailing data", ErrInvalidResponse)
	}
	if r.Active == nil {
		return response{}, fmt.Errorf("%w: missing active", ErrInvalidResponse)
	}
	return r, nil
}

func do(client *http.Client, req *http.Request) (body []byte, err error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer func() {
		if cerr := resp.Body.Close(); cerr != nil && err == nil {
			body, err = nil, fmt.Errorf("%w: %w", ErrUnavailable, cerr)
		}
	}()
	body, err = io.ReadAll(io.LimitReader(resp.Body, MaxResponseSize+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if resp.StatusCode >= http.StatusInternalServerError {
		return nil, fmt.Errorf("%w: status %d", ErrUnavailable, resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrInvalidResponse, resp.StatusCode)
	}
	if len(body) > MaxResponseSize {
		return nil, fmt.Errorf("%w: body larger than %d bytes", ErrInvalidResponse, MaxResponseSize)
	}
	if mt, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type")); err != nil || mt != jsonContentType {
		return nil, fmt.Errorf("%w: content type %q", ErrInvalidResponse, resp.Header.Get("Content-Type"))
	}
	return body, nil
}
