// Package integration runs the relay binary between an SSH client and server.
package integration

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"go.uber.org/goleak"
	"golang.org/x/crypto/ssh"

	"github.com/parallelworks/relay/dpop"
	"github.com/parallelworks/relay/internal/fakeas"
	"github.com/parallelworks/relay/internal/rawconnect"
	"github.com/parallelworks/relay/internal/testpki"
)

const (
	gib            = 1 << 30
	sessionCheck   = 200 * time.Millisecond
	certReload     = 100 * time.Millisecond
	sparseFileName = "sparse"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

var sshAlgorithms = ssh.Config{
	KeyExchanges: []string{"ecdh-sha2-nistp256"},
	Ciphers:      []string{"aes128-ctr"},
	MACs:         []string{"hmac-sha2-256-etm@openssh.com"},
}

func must(t testing.TB, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

type sshServer struct {
	addr    string
	hostKey ssh.PublicKey
	dir     string
}

func startSSH(t *testing.T, clientKey ssh.PublicKey) *sshServer {
	t.Helper()
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	signer, err := ssh.NewSignerFromKey(hostKey)
	must(t, err)
	cfg := &ssh.ServerConfig{
		Config: sshAlgorithms,
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), clientKey.Marshal()) {
				return &ssh.Permissions{}, nil
			}
			return nil, errors.New("unknown key")
		},
	}
	cfg.AddHostKey(signer)
	s := &sshServer{hostKey: signer.PublicKey(), dir: t.TempDir()}
	f, err := os.Create(filepath.Join(s.dir, sparseFileName))
	must(t, err)
	must(t, errors.Join(f.Truncate(gib), f.Close()))

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	must(t, err)
	s.addr = ln.Addr().String()
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			wg.Go(func() { s.serve(t, c, cfg) })
		}
	})
	t.Cleanup(func() {
		must(t, ln.Close())
		wg.Wait()
	})
	return s
}

func (s *sshServer) serve(t *testing.T, c net.Conn, cfg *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		t.Log("ssh handshake:", err)
		return
	}
	var wg sync.WaitGroup
	wg.Go(func() { ssh.DiscardRequests(reqs) })
	for nc := range chans {
		if nc.ChannelType() != "session" {
			if err := nc.Reject(ssh.UnknownChannelType, "only sessions"); err != nil {
				t.Log(err)
			}
			continue
		}
		ch, chReqs, err := nc.Accept()
		if err != nil {
			t.Log(err)
			continue
		}
		wg.Go(func() { s.session(t, conn.User(), ch, chReqs) })
	}
	wg.Wait()
}

func (s *sshServer) session(t *testing.T, user string, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer func() {
		if err := ch.Close(); err != nil && !errors.Is(err, io.EOF) {
			t.Log(err)
		}
	}()
	for req := range reqs {
		switch req.Type {
		case "exec":
			var cmd struct{ Command string }
			if err := ssh.Unmarshal(req.Payload, &cmd); err != nil || cmd.Command != "whoami" {
				reply(t, req, false)
				continue
			}
			reply(t, req, true)
			_, err := fmt.Fprintln(ch, user)
			status := struct{ Status uint32 }{0}
			if err == nil {
				_, err = ch.SendRequest("exit-status", false, ssh.Marshal(&status))
			}
			if err != nil {
				t.Log(err)
			}
			return
		case "subsystem":
			var sub struct{ Name string }
			if err := ssh.Unmarshal(req.Payload, &sub); err != nil || sub.Name != "sftp" {
				reply(t, req, false)
				continue
			}
			reply(t, req, true)
			srv, err := sftp.NewServer(ch, sftp.WithServerWorkingDirectory(s.dir))
			if err != nil {
				t.Log(err)
				return
			}
			if err := srv.Serve(); err != nil && !errors.Is(err, io.EOF) {
				t.Log("sftp:", err)
			}
			return
		default:
			reply(t, req, false)
		}
	}
}

func reply(t *testing.T, req *ssh.Request, ok bool) {
	if req.WantReply {
		if err := req.Reply(ok, nil); err != nil {
			t.Log(err)
		}
	}
}

type relayProcess struct {
	addr  string
	cmd   *exec.Cmd
	mu    sync.Mutex
	logs  bytes.Buffer
	ended chan struct{}
}

func (p *relayProcess) Logs() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.logs.String()
}

func buildRelay(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "relay")
	cmd := exec.CommandContext(t.Context(), "go", "build", "-trimpath", "-o", bin, "./cmd/relay") //nolint:gosec // G204: builds the relay into the test's temporary directory.
	cmd.Dir = ".."
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	return bin
}

func startRelay(t *testing.T, bin, config string) *relayProcess {
	t.Helper()
	ctx, cancel := context.WithCancel(context.WithoutCancel(t.Context()))
	t.Cleanup(cancel)
	p := &relayProcess{cmd: exec.CommandContext(ctx, bin, "-config", config), ended: make(chan struct{})} //nolint:gosec // G204: the binary the test just built.
	p.cmd.Env = append(os.Environ(), "GODEBUG=")
	stderr, err := p.cmd.StderrPipe()
	must(t, err)
	must(t, p.cmd.Start())
	started := make(chan string, 1)
	go func() {
		defer close(p.ended)
		sc := bufio.NewScanner(stderr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			line := sc.Bytes()
			p.mu.Lock()
			p.logs.Write(line)
			p.logs.WriteByte('\n')
			p.mu.Unlock()
			var rec struct {
				Msg    string `json:"msg"`
				Listen string `json:"listen"`
			}
			if json.Unmarshal(line, &rec) == nil && rec.Msg == "relay.started" {
				started <- rec.Listen
			}
		}
	}()
	select {
	case p.addr = <-started:
	case <-p.ended:
		t.Fatalf("relay exited:\n%s", p.Logs())
	case <-time.After(30 * time.Second):
		t.Fatalf("relay did not start:\n%s", p.Logs())
	}
	return p
}

func (p *relayProcess) stop(t *testing.T) {
	t.Helper()
	must(t, p.cmd.Process.Signal(syscall.SIGTERM))
	<-p.ended
	if err := p.cmd.Wait(); err != nil {
		t.Fatalf("relay exited with %v:\n%s", err, p.Logs())
	}
}

type tunnelConn struct {
	rawconnect.Conn
	addr net.Addr
}

func (c tunnelConn) LocalAddr() net.Addr              { return c.addr }
func (c tunnelConn) RemoteAddr() net.Addr             { return c.addr }
func (c tunnelConn) SetDeadline(time.Time) error      { return nil }
func (c tunnelConn) SetReadDeadline(time.Time) error  { return nil }
func (c tunnelConn) SetWriteDeadline(time.Time) error { return nil }

type env struct {
	as       *fakeas.AS
	relay    *relayProcess
	roots    *x509.CertPool
	clientID string
	prover   *dpop.Prover
	ssh      *sshServer
	sshKey   ssh.Signer
}

func (e *env) dial(t *testing.T, session string) *ssh.Client {
	t.Helper()
	target := e.ssh.addr
	token := e.as.Issue(&fakeas.Grant{
		Subject: "alice", Audience: []string{e.clientID}, JKT: e.prover.Thumbprint(), Target: target,
		Session: session, Expires: time.Now().Add(time.Hour),
	})
	proof, err := e.prover.Proof(http.MethodConnect, dpop.TargetURI(target), token, "")
	must(t, err)
	h := http.Header{"Authorization": {"DPoP " + token}, "Dpop": {proof}}
	resp, conn, err := rawconnect.Do(t.Context(), &rawconnect.Request{Addr: e.relay.addr, Roots: e.roots, Authority: target, Header: h})
	must(t, err)
	if conn == nil {
		t.Fatalf("status %d: %s\n%s", resp.StatusCode, resp.Body, e.relay.Logs())
	}
	addr, err := net.ResolveTCPAddr("tcp", target)
	must(t, err)
	sc, chans, reqs, err := ssh.NewClientConn(tunnelConn{Conn: conn, addr: addr}, target, &ssh.ClientConfig{
		Config:            sshAlgorithms,
		User:              "alice",
		Auth:              []ssh.AuthMethod{ssh.PublicKeys(e.sshKey)},
		HostKeyCallback:   ssh.FixedHostKey(e.ssh.hostKey),
		HostKeyAlgorithms: []string{ssh.KeyAlgoECDSA256},
	})
	must(t, err)
	client := ssh.NewClient(sc, chans, reqs)
	t.Cleanup(func() {
		if err := client.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
			t.Log(err)
		}
	})
	return client
}

func whoami(client *ssh.Client) (string, error) {
	s, err := client.NewSession()
	if err != nil {
		return "", err
	}
	out, err := s.Output("whoami")
	if cerr := s.Close(); cerr != nil && !errors.Is(cerr, io.EOF) {
		err = errors.Join(err, cerr)
	}
	return strings.TrimSpace(string(out)), err
}

type pattern struct {
	block []byte
	off   int
}

func (p *pattern) Read(b []byte) (int, error) {
	n := 0
	for n < len(b) {
		c := copy(b[n:], p.block[p.off:])
		n += c
		p.off = (p.off + c) % len(p.block)
	}
	return n, nil
}

func newEnv(t *testing.T) (e *env, configPath string) {
	t.Helper()
	dir := t.TempDir()
	e = &env{as: fakeas.New(t)}
	ca := testpki.New(t)
	e.roots = ca.Pool()
	tlsDir := filepath.Join(dir, "tls")
	regDir := filepath.Join(dir, "registration")
	for _, d := range []string{tlsDir, regDir} {
		must(t, os.Mkdir(d, 0o700))
	}
	writeCert(t, ca, tlsDir)
	write := func(name string, data []byte) string {
		path := filepath.Join(dir, name)
		must(t, os.WriteFile(path, data, 0o600))
		return path
	}
	config, err := json.Marshal(map[string]any{
		"listen":         "127.0.0.1:0",
		"issuer":         e.as.Issuer(),
		"issuer_ca_file": write("ca.pem", e.as.CAPEM()),
		"tls":            map[string]any{"dir": tlsDir, "reload_interval": certReload.String()},
		"registration":   map[string]any{"dir": regDir, "initial_access_token_file": write("iat", []byte(e.as.InitialAccessToken()))},
		"egress":         map[string]any{"allow": []string{"127.0.0.0/8"}, "exceptions": []string{"127.0.0.1"}},
		"session":        map[string]any{"interval": sessionCheck.String()},
	})
	must(t, err)

	key, err := dpop.GenerateKey()
	must(t, err)
	e.prover, err = dpop.NewProver(key)
	must(t, err)
	sshKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(t, err)
	e.sshKey, err = ssh.NewSignerFromKey(sshKey)
	must(t, err)
	e.ssh = startSSH(t, e.sshKey.PublicKey())

	rec, err := os.ReadFile(filepath.Join(regDir, "relay-client.json")) //nolint:gosec // G304: a path under t.TempDir.
	if err == nil {
		t.Fatalf("registration exists before the relay started: %s", rec)
	}
	return e, write("config.json", config)
}

func writeCert(t *testing.T, ca *testpki.CA, dir string) {
	t.Helper()
	certPEM, keyPEM := ca.LeafPEM(t, "127.0.0.1")
	must(t, os.WriteFile(filepath.Join(dir, "tls.key.tmp"), keyPEM, 0o600))
	must(t, os.WriteFile(filepath.Join(dir, "tls.crt.tmp"), certPEM, 0o600))
	must(t, os.Rename(filepath.Join(dir, "tls.key.tmp"), filepath.Join(dir, "tls.key")))
	must(t, os.Rename(filepath.Join(dir, "tls.crt.tmp"), filepath.Join(dir, "tls.crt")))
}

func readClientID(t *testing.T, config string) string {
	t.Helper()
	var cfg struct {
		Registration struct {
			Dir string `json:"dir"`
		} `json:"registration"`
	}
	data, err := os.ReadFile(config) //nolint:gosec // G304: the file the test wrote.
	must(t, err)
	must(t, json.Unmarshal(data, &cfg))
	rec, err := os.ReadFile(filepath.Join(cfg.Registration.Dir, "relay-client.json"))
	must(t, err)
	var stored struct {
		ClientID string `json:"client_id"`
	}
	must(t, json.Unmarshal(rec, &stored))
	return stored.ClientID
}

func TestRelayCarriesSSH(t *testing.T) {
	e, config := newEnv(t)
	e.relay = startRelay(t, buildRelay(t), config)
	t.Cleanup(func() { e.relay.stop(t) })
	if !strings.Contains(e.relay.Logs(), `"fips140_enforced":true`) {
		t.Fatalf("the relay binary does not enforce FIPS 140-3 mode:\n%s", e.relay.Logs())
	}
	e.clientID = readClientID(t, config)

	client := e.dial(t, "session-main")
	t.Run("interactive session", func(t *testing.T) {
		if who, err := whoami(client); err != nil || who != "alice" {
			t.Fatalf("whoami = %q, %v", who, err)
		}
	})

	t.Run("sftp 1 GiB", func(t *testing.T) {
		sc, err := sftp.NewClient(client, sftp.UseConcurrentWrites(true), sftp.MaxConcurrentRequestsPerFile(64))
		must(t, err)
		defer func() { must(t, sc.Close()) }()
		block := make([]byte, 1<<20)
		_, err = rand.Read(block)
		must(t, err)
		f, err := sc.Create("upload")
		must(t, err)
		sent := sha256.New()
		start := time.Now()
		n, err := f.ReadFrom(io.TeeReader(io.LimitReader(&pattern{block: block}, gib), sent))
		must(t, errors.Join(err, f.Close()))
		elapsed := time.Since(start)
		if n != gib {
			t.Fatalf("sent %d bytes", n)
		}
		t.Logf("uploaded 1 GiB in %v (%.0f MiB/s)", elapsed, float64(gib)/(1<<20)/elapsed.Seconds())
		got, err := os.Open(filepath.Join(e.ssh.dir, "upload"))
		must(t, err)
		received := sha256.New()
		_, err = io.Copy(received, got)
		must(t, errors.Join(err, got.Close()))
		if !bytes.Equal(sent.Sum(nil), received.Sum(nil)) {
			t.Fatal("the file on the server differs from what was sent")
		}
	})

	t.Run("certificate rotation mid-run", func(t *testing.T) {
		next := testpki.New(t)
		writeCert(t, next, filepath.Join(filepath.Dir(config), "tls"))
		deadline := time.Now().Add(10 * time.Second)
		for {
			d := &tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: next.Pool()}}
			c, err := d.DialContext(t.Context(), "tcp", e.relay.addr)
			if err == nil {
				must(t, c.Close())
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("new certificate not served: %v", err)
			}
			time.Sleep(certReload / 2)
		}
		if who, err := whoami(client); err != nil || who != "alice" {
			t.Fatalf("tunnel opened before rotation broke: %q, %v", who, err)
		}
		e.roots = next.Pool()
		if who, err := whoami(e.dial(t, "session-after-rotation")); err != nil || who != "alice" {
			t.Fatalf("tunnel after rotation: %q, %v", who, err)
		}
	})

	t.Run("revocation mid-transfer", func(t *testing.T) {
		revoked := e.dial(t, "session-revoked")
		sc, err := sftp.NewClient(revoked)
		must(t, err)
		defer func() {
			if cerr := sc.Close(); cerr != nil {
				t.Log(cerr)
			}
		}()
		f, err := sc.Open(sparseFileName)
		must(t, err)
		defer func() {
			if cerr := f.Close(); cerr != nil {
				t.Log(cerr)
			}
		}()
		head := make([]byte, 32<<20)
		_, err = io.ReadFull(f, head)
		must(t, err)
		e.as.SetSession("session-revoked", "alice", false)
		revokedAt := time.Now()
		n, err := io.Copy(io.Discard, f)
		if err == nil {
			t.Fatalf("download of %d more bytes completed after revocation", n)
		}
		if took := time.Since(revokedAt); took > 10*sessionCheck {
			t.Fatalf("tunnel closed %v after revocation", took)
		}
		if who, err := whoami(client); err != nil || who != "alice" {
			t.Fatalf("revocation closed another session's tunnel: %q, %v", who, err)
		}
		deadline := time.Now().Add(5 * time.Second)
		for !strings.Contains(e.relay.Logs(), `"close_reason":"revoked"`) {
			if time.Now().After(deadline) {
				t.Fatalf("no revoked tunnel.closed record:\n%s", e.relay.Logs())
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}
