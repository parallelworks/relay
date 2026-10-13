package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// MaxConfigSize caps the configuration file.
const MaxConfigSize = 1 << 20

// Duration is a time.Duration written as a Go duration string, such as "90s".
type Duration time.Duration

// UnmarshalText parses a Go duration string.
func (d *Duration) UnmarshalText(b []byte) error {
	v, err := time.ParseDuration(string(b))
	if err != nil {
		return err
	}
	if v < 0 {
		return fmt.Errorf("negative duration %q", b)
	}
	*d = Duration(v)
	return nil
}

// Config is the relay's configuration file.
type Config struct {
	Listen          string       `json:"listen"`
	Issuer          string       `json:"issuer"`
	IssuerCAFile    string       `json:"issuer_ca_file"`
	TLS             TLS          `json:"tls"`
	Registration    Registration `json:"registration"`
	Egress          Egress       `json:"egress"`
	DPoPNonces      *DPoPNonces  `json:"dpop_nonces"`
	Session         Session      `json:"session"`
	Limits          Limits       `json:"limits"`
	ShutdownTimeout Duration     `json:"shutdown_timeout"`
	LogLevel        slog.Level   `json:"log_level"`
}

// TLS locates the relay's certificate and key.
type TLS struct {
	Dir            string   `json:"dir"`
	Cert           string   `json:"cert"`
	Key            string   `json:"key"`
	ReloadInterval Duration `json:"reload_interval"`
}

// Registration locates the relay's stored credentials and how to obtain them.
type Registration struct {
	Dir                    string `json:"dir"`
	ClientName             string `json:"client_name"`
	InitialAccessTokenFile string `json:"initial_access_token_file"`
}

// Egress is the egress policy.
type Egress struct {
	Allow      []netip.Prefix `json:"allow"`
	Exceptions []netip.Addr   `json:"exceptions"`
}

// DPoPNonces turns on server-provided DPoP nonces (RFC 9449 §9).
type DPoPNonces struct {
	Lifetime Duration `json:"lifetime"`
	// KeyFile holds a key of at least 32 bytes shared by every replica, so a nonce one replica issues is
	// valid at another. Without it each process uses its own random key.
	KeyFile string `json:"key_file"`
}

// Session configures re-introspection of open tunnels.
type Session struct {
	Interval Duration `json:"interval"`
	Grace    Duration `json:"grace"`
}

// Limits mirror server.Limits.
type Limits struct {
	MaxTunnels           int      `json:"max_tunnels"`
	MaxTunnelsPerSource  int      `json:"max_tunnels_per_source"`
	MaxConnsPerSource    int      `json:"max_conns_per_source"`
	FailedAuthPerMinute  int      `json:"failed_auth_per_minute"`
	DialTimeout          Duration `json:"dial_timeout"`
	IntrospectionTimeout Duration `json:"introspection_timeout"`
	ReadHeaderTimeout    Duration `json:"read_header_timeout"`
	IdleTimeout          Duration `json:"idle_timeout"`
	MaxTunnelLifetime    Duration `json:"max_tunnel_lifetime"`
}

func decodeConfig(data []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	c := &Config{}
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("config: data after the configuration object")
	}
	c.defaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) defaults() {
	if c.Listen == "" {
		c.Listen = ":8443"
	}
	if c.TLS.Cert == "" {
		c.TLS.Cert = "tls.crt"
	}
	if c.TLS.Key == "" {
		c.TLS.Key = "tls.key"
	}
	if c.TLS.ReloadInterval == 0 {
		c.TLS.ReloadInterval = Duration(time.Minute)
	}
	if c.ShutdownTimeout == 0 {
		c.ShutdownTimeout = Duration(30 * time.Second)
	}
	if c.DPoPNonces != nil && c.DPoPNonces.Lifetime == 0 {
		c.DPoPNonces.Lifetime = Duration(5 * time.Minute)
	}
}

func (c *Config) validate() error {
	u, err := url.Parse(c.Issuer)
	var errs []error
	if err != nil || u.Scheme != "https" || u.Host == "" {
		errs = append(errs, errors.New("issuer must be an https URL"))
	}
	if c.TLS.Dir == "" {
		errs = append(errs, errors.New("tls.dir is required"))
	}
	if c.Registration.Dir == "" {
		errs = append(errs, errors.New("registration.dir is required"))
	}
	if len(c.Egress.Allow) == 0 {
		errs = append(errs, errors.New("egress.allow must list at least one prefix"))
	}
	if err := errors.Join(errs...); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	return nil
}

// readFile reads path through an os.Root on its directory, so a symbolic link cannot lead outside it.
func readFile(path string) ([]byte, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	data, err := root.ReadFile(filepath.Base(path))
	return data, errors.Join(err, root.Close())
}
