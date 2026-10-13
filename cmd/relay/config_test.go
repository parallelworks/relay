package main

import (
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"
)

const minimal = `{
	"issuer": "https://as.example",
	"tls": {"dir": "/etc/relay/tls"},
	"registration": {"dir": "/var/lib/relay"},
	"egress": {"allow": ["10.0.0.0/8"]}
}`

func TestDecodeConfigDefaults(t *testing.T) {
	t.Parallel()
	c, err := decodeConfig([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8443" || c.TLS.Cert != "tls.crt" || c.TLS.Key != "tls.key" ||
		time.Duration(c.TLS.ReloadInterval) != time.Minute || time.Duration(c.ShutdownTimeout) != 30*time.Second ||
		c.LogLevel != slog.LevelInfo || c.DPoPNonces != nil {
		t.Fatalf("defaults %+v", c)
	}
	if c.Egress.Allow[0] != netip.MustParsePrefix("10.0.0.0/8") {
		t.Fatalf("allow %v", c.Egress.Allow)
	}
}

func TestDecodeConfigFull(t *testing.T) {
	t.Parallel()
	c, err := decodeConfig([]byte(`{
		"listen": "127.0.0.1:9443",
		"issuer": "https://as.example/tenant",
		"issuer_ca_file": "/etc/relay/ca.pem",
		"tls": {"dir": "/tls", "cert": "c.pem", "key": "k.pem", "reload_interval": "10s"},
		"registration": {"dir": "/reg", "client_name": "relay-a", "initial_access_token_file": "/secrets/iat"},
		"egress": {"allow": ["10.0.0.0/8", "2001:db8::/32"], "exceptions": ["10.0.0.1"]},
		"dpop_nonces": {"key_file": "/secrets/nonce"},
		"session": {"interval": "30s", "grace": "1m"},
		"limits": {"max_tunnels": 5, "max_tunnels_per_source": 2, "max_conns_per_source": 3, "failed_auth_per_minute": 4,
			"dial_timeout": "1s", "introspection_timeout": "2s", "read_header_timeout": "3s", "idle_timeout": "4h"},
		"shutdown_timeout": "5m",
		"log_level": "DEBUG"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	if c.DPoPNonces == nil || time.Duration(c.DPoPNonces.Lifetime) != 5*time.Minute || c.DPoPNonces.KeyFile != "/secrets/nonce" {
		t.Fatalf("nonces %+v", c.DPoPNonces)
	}
	if c.Limits.MaxTunnels != 5 || time.Duration(c.Limits.IdleTimeout) != 4*time.Hour || c.LogLevel != slog.LevelDebug {
		t.Fatalf("config %+v", c)
	}
	if time.Duration(c.Session.Grace) != time.Minute {
		t.Fatalf("grace %v", c.Session.Grace)
	}
}

func TestDecodeConfigRejects(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"unknown field":      `{"issuer": "https://a", "tls": {"dir": "d"}, "registration": {"dir": "d"}, "egress": {"allow": ["10.0.0.0/8"]}, "extra": 1}`,
		"trailing data":      minimal + `{}`,
		"not json":           `issuer: x`,
		"http issuer":        strings.Replace(minimal, "https://as.example", "http://as.example", 1),
		"no tls dir":         strings.Replace(minimal, `"dir": "/etc/relay/tls"`, `"cert": "c"`, 1),
		"no registration":    strings.Replace(minimal, `"dir": "/var/lib/relay"`, `"client_name": "c"`, 1),
		"empty egress":       strings.Replace(minimal, `["10.0.0.0/8"]`, `[]`, 1),
		"bad prefix":         strings.Replace(minimal, `10.0.0.0/8`, `10.0.0.0/33`, 1),
		"bad duration":       strings.Replace(minimal, `"egress"`, `"shutdown_timeout": "soon", "egress"`, 1),
		"negative duration":  strings.Replace(minimal, `"egress"`, `"shutdown_timeout": "-1s", "egress"`, 1),
		"unknown nested key": strings.Replace(minimal, `"dir": "/etc/relay/tls"`, `"dir": "/etc/relay/tls", "min_version": "1.2"`, 1),
	}
	for name, in := range cases {
		if _, err := decodeConfig([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
