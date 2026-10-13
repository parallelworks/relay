package main

import (
	"net/url"
	"testing"
)

func FuzzDecodeConfig(f *testing.F) {
	f.Add([]byte(`{"issuer": "https://as.example", "tls": {"dir": "t"}, "registration": {"dir": "r"}, "egress": {"allow": ["10.0.0.0/8"]}}`))
	f.Add([]byte(`{"issuer": "https://a", "dpop_nonces": {}, "limits": {"idle_timeout": "1h"}, "log_level": "WARN"}`))
	f.Add([]byte(`{} {}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := decodeConfig(data)
		if err != nil {
			return
		}
		u, err := url.Parse(c.Issuer)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			t.Fatalf("accepted issuer %q", c.Issuer)
		}
		if c.TLS.Dir == "" || c.Registration.Dir == "" || len(c.Egress.Allow) == 0 {
			t.Fatalf("accepted incomplete config %+v", c)
		}
		if c.ShutdownTimeout <= 0 || c.TLS.ReloadInterval <= 0 || c.Listen == "" {
			t.Fatalf("defaults missing %+v", c)
		}
	})
}
