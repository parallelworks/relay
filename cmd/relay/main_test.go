package main

import (
	"bytes"
	"context"
	"crypto/fips140"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/parallelworks/relay/dpop"
	"github.com/parallelworks/relay/internal/fakeas"
	"github.com/parallelworks/relay/internal/rawconnect"
	"github.com/parallelworks/relay/internal/relaytest"
	"github.com/parallelworks/relay/internal/testpki"
	"github.com/parallelworks/relay/registration"
)

// net/http keeps a connection it closes after a response for a fixed 500 ms, to avoid a TCP reset.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m, goleak.IgnoreAnyFunction("net/http.(*conn).closeWriteAndWait"))
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type setup struct {
	as      *fakeas.AS
	ca      *testpki.CA
	dir     string
	regDir  string
	config  map[string]any
	logs    *syncBuffer
	tokenFn string
}

func write(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func newSetup(t *testing.T) *setup {
	t.Helper()
	s := &setup{as: fakeas.New(t), ca: testpki.New(t), dir: t.TempDir(), logs: &syncBuffer{}}
	tlsDir := filepath.Join(s.dir, "tls")
	s.regDir = filepath.Join(s.dir, "registration")
	for _, d := range []string{tlsDir, s.regDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	certPEM, keyPEM := s.ca.LeafPEM(t, "127.0.0.1")
	write(t, filepath.Join(tlsDir, "tls.crt"), certPEM)
	write(t, filepath.Join(tlsDir, "tls.key"), keyPEM)
	write(t, filepath.Join(s.dir, "ca.pem"), s.as.CAPEM())
	s.tokenFn = filepath.Join(s.dir, "iat")
	write(t, s.tokenFn, []byte(s.as.InitialAccessToken()+"\n"))
	s.config = map[string]any{
		"listen":         "127.0.0.1:0",
		"issuer":         s.as.Issuer(),
		"issuer_ca_file": filepath.Join(s.dir, "ca.pem"),
		"tls":            map[string]any{"dir": tlsDir},
		"registration":   map[string]any{"dir": s.regDir, "client_name": "test", "initial_access_token_file": s.tokenFn},
		"egress":         map[string]any{"allow": []string{"127.0.0.0/8"}, "exceptions": []string{"127.0.0.1"}},
		"session":        map[string]any{"interval": "50ms"},
		"log_level":      "DEBUG",
	}
	return s
}

func (s *setup) writeConfig(t *testing.T) string {
	t.Helper()
	data, err := json.Marshal(s.config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.dir, "config.json")
	write(t, path, data)
	return path
}

type running struct {
	addr string
	stop func() error
}

func (s *setup) start(t *testing.T) *running {
	t.Helper()
	path := s.writeConfig(t)
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	ready := make(chan net.Addr, 1)
	go func() {
		done <- run(ctx, []string{"-config", path}, io.Discard, s.logs, func(a net.Addr) { ready <- a })
	}()
	r := &running{stop: sync.OnceValue(func() error {
		cancel()
		return <-done
	})}
	select {
	case a := <-ready:
		r.addr = a.String()
	case err := <-done:
		cancel()
		t.Fatalf("run = %v\n%s", err, s.logs)
	}
	t.Cleanup(func() {
		if err := r.stop(); err != nil {
			t.Error(err)
		}
	})
	return r
}

func (s *setup) clientID(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(s.regDir, registration.DefaultClientName))
	if err != nil {
		t.Fatal(err)
	}
	var rec struct {
		ClientID string `json:"client_id"`
	}
	if err := json.Unmarshal(data, &rec); err != nil {
		t.Fatal(err)
	}
	return rec.ClientID
}

func (s *setup) open(t *testing.T, r *running) rawconnect.Conn {
	t.Helper()
	echo := relaytest.StartEcho(t)
	key, err := dpop.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	prover, err := dpop.NewProver(key)
	if err != nil {
		t.Fatal(err)
	}
	token := s.as.Issue(&fakeas.Grant{
		Subject: "alice", Audience: []string{s.clientID(t)}, JKT: prover.Thumbprint(), Target: echo.String(),
		Session: "session-" + rand.Text(), Expires: time.Now().Add(time.Minute),
	})
	proof, err := prover.Proof(http.MethodConnect, dpop.TargetURI(echo.String()), token, "")
	if err != nil {
		t.Fatal(err)
	}
	h := http.Header{"Authorization": {"DPoP " + token}, "Dpop": {proof}}
	resp, conn, err := rawconnect.Do(t.Context(), &rawconnect.Request{Addr: r.addr, Roots: s.ca.Pool(), Authority: echo.String(), Header: h})
	if err != nil {
		t.Fatal(err)
	}
	if conn == nil {
		t.Fatalf("status %d: %s\n%s", resp.StatusCode, resp.Body, s.logs)
	}
	return conn
}

func (s *setup) tunnel(t *testing.T, r *running) {
	t.Helper()
	conn := s.open(t, r)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Log(err)
		}
	}()
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(conn)
	if err != nil || string(got) != "hello" {
		t.Fatalf("echo %q, %v", got, err)
	}
}

func TestRunRegistersAndServes(t *testing.T) {
	t.Parallel()
	s := newSetup(t)
	r := s.start(t)
	s.tunnel(t, r)
	if err := r.stop(); err != nil {
		t.Fatal(err)
	}
	if n := len(s.as.Registrations()); n != 1 {
		t.Fatalf("%d registrations", n)
	}
	logs := s.logs.String()
	for _, want := range []string{`"msg":"relay.started"`, `"fips140_enforced":true`, `"msg":"tunnel.closed"`, `"msg":"relay.stopping"`} {
		if !strings.Contains(logs, want) {
			t.Errorf("logs lack %s", want)
		}
	}

	s.config["registration"] = map[string]any{"dir": s.regDir}
	s.config["dpop_nonces"] = map[string]any{}
	s.start(t)
	if n := len(s.as.Registrations()); n != 1 {
		t.Fatalf("registered again: %d registrations", n)
	}
}

func TestRegisterOnly(t *testing.T) {
	t.Parallel()
	s := newSetup(t)
	path := s.writeConfig(t)
	for range 2 {
		var out bytes.Buffer
		if err := run(t.Context(), []string{"-register", "-config", path}, &out, io.Discard, nil); err != nil {
			t.Fatal(err)
		}
		if want := "client_id " + s.clientID(t) + "\n"; out.String() != want {
			t.Fatalf("output %q, want %q", out.String(), want)
		}
	}
	if n := len(s.as.Registrations()); n != 1 {
		t.Fatalf("%d registrations", n)
	}
	s.config["issuer_ca_file"] = filepath.Join(s.dir, "none.pem")
	if err := run(t.Context(), []string{"-register", "-config", s.writeConfig(t)}, io.Discard, io.Discard, nil); err == nil {
		t.Fatal("register succeeded without the CA file")
	}
}

func TestRunWithSharedNonceKey(t *testing.T) {
	t.Parallel()
	s := newSetup(t)
	keyFile := filepath.Join(s.dir, "nonce.key")
	write(t, keyFile, bytes.Repeat([]byte{7}, 32))
	s.config["dpop_nonces"] = map[string]any{"key_file": keyFile, "lifetime": "1m"}
	s.start(t)
}

func TestRunVersion(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	if err := run(t.Context(), []string{"-version"}, &out, io.Discard, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out.String(), "relay ") || !strings.Contains(out.String(), "enforced true") {
		t.Fatalf("version output %q", out.String())
	}
}

func TestRunFailures(t *testing.T) {
	t.Parallel()
	cases := map[string]func(t *testing.T, s *setup) []string{
		"unknown flag": func(*testing.T, *setup) []string { return []string{"-nope"} },
		"missing config": func(_ *testing.T, s *setup) []string {
			return []string{"-config", filepath.Join(s.dir, "missing.json")}
		},
		"oversized config": func(t *testing.T, s *setup) []string {
			path := filepath.Join(s.dir, "big.json")
			write(t, path, bytes.Repeat([]byte(" "), MaxConfigSize+1))
			return []string{"-config", path}
		},
		"invalid config": func(t *testing.T, s *setup) []string {
			s.config["issuer"] = "http://insecure"
			return []string{"-config", s.writeConfig(t)}
		},
		"missing CA file": func(t *testing.T, s *setup) []string {
			s.config["issuer_ca_file"] = filepath.Join(s.dir, "none.pem")
			return []string{"-config", s.writeConfig(t)}
		},
		"CA file without certificates": func(t *testing.T, s *setup) []string {
			write(t, filepath.Join(s.dir, "ca.pem"), []byte("nothing"))
			return []string{"-config", s.writeConfig(t)}
		},
		"untrusted issuer": func(t *testing.T, s *setup) []string {
			write(t, filepath.Join(s.dir, "ca.pem"), testpki.New(t).CertPEM())
			return []string{"-config", s.writeConfig(t)}
		},
		"unregistered without a token": func(t *testing.T, s *setup) []string {
			s.config["registration"] = map[string]any{"dir": s.regDir}
			return []string{"-config", s.writeConfig(t)}
		},
		"missing token file": func(t *testing.T, s *setup) []string {
			s.config["registration"] = map[string]any{"dir": s.regDir, "initial_access_token_file": filepath.Join(s.dir, "none")}
			return []string{"-config", s.writeConfig(t)}
		},
		"missing registration dir": func(t *testing.T, s *setup) []string {
			s.config["registration"] = map[string]any{"dir": filepath.Join(s.dir, "none")}
			return []string{"-config", s.writeConfig(t)}
		},
		"invalid egress": func(t *testing.T, s *setup) []string {
			s.config["egress"] = map[string]any{"allow": []string{"10.0.0.0/8"}, "exceptions": []string{"fe80::1%eth0"}}
			return []string{"-config", s.writeConfig(t)}
		},
		"short nonce key": func(t *testing.T, s *setup) []string {
			keyFile := filepath.Join(s.dir, "nonce.key")
			write(t, keyFile, []byte("short"))
			s.config["dpop_nonces"] = map[string]any{"key_file": keyFile}
			return []string{"-config", s.writeConfig(t)}
		},
		"missing nonce key": func(t *testing.T, s *setup) []string {
			s.config["dpop_nonces"] = map[string]any{"key_file": filepath.Join(s.dir, "none")}
			return []string{"-config", s.writeConfig(t)}
		},
		"missing certificate": func(t *testing.T, s *setup) []string {
			s.config["tls"] = map[string]any{"dir": s.dir}
			return []string{"-config", s.writeConfig(t)}
		},
		"unusable listen address": func(t *testing.T, s *setup) []string {
			s.config["listen"] = "192.0.2.1:1"
			return []string{"-config", s.writeConfig(t)}
		},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			s := newSetup(t)
			if err := run(t.Context(), args(t, s), io.Discard, io.Discard, nil); err == nil {
				t.Fatal("run succeeded")
			}
		})
	}
}

func TestRunsInFIPSOnlyMode(t *testing.T) {
	t.Parallel()
	if !fips140.Enabled() || !fips140.Enforced() {
		t.Fatal("the relay's packages are not running with fips140=only")
	}
	bin := filepath.Join(t.TempDir(), "relay")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", bin, ".") //nolint:gosec // G204: builds this package into the test's temporary directory.
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	cmd := exec.CommandContext(t.Context(), bin, "-version") //nolint:gosec // G204: the binary the test just built.
	cmd.Env = append(os.Environ(), "GODEBUG=")
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(out), "enabled true, enforced true") {
		t.Fatalf("the binary does not enforce FIPS 140-3 mode on its own: %s", out)
	}
	if mode := os.Getenv("GOFIPS140"); mode != "" && mode != "off" && strings.Contains(string(out), "module latest") {
		t.Fatalf("built with GOFIPS140=%s but runs the unfrozen module: %s", mode, out)
	}
}

func TestShutdownTimeout(t *testing.T) {
	t.Parallel()
	s := newSetup(t)
	s.config["shutdown_timeout"] = "1ms"
	r := s.start(t)
	conn := s.open(t, r)
	defer func() {
		if err := conn.Close(); err != nil {
			t.Log(err)
		}
	}()
	if err := r.stop(); err != nil {
		t.Fatalf("a shutdown that times out is not an error: %v", err)
	}
	if !strings.Contains(s.logs.String(), "relay.shutdown_timeout") {
		t.Fatal("timeout not logged")
	}
}
