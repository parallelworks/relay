package client_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/parallelworks/relay/client"
	"github.com/parallelworks/relay/internal/relaytest"
	"github.com/parallelworks/relay/introspect"
	"github.com/parallelworks/relay/server"
)

// net/http keeps a connection it closes after a response for a fixed 500 ms, to avoid a TCP reset.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m, goleak.IgnoreAnyFunction("net/http.(*conn).closeWriteAndWait"))
}

type env struct {
	*relaytest.Env
	key *ecdsa.PrivateKey
}

func start(t *testing.T, opts *relaytest.Options) *env {
	t.Helper()
	e := relaytest.Start(t, opts)
	return &env{Env: e, key: e.Key}
}

type rejections struct {
	mu sync.Mutex
	n  int
}

func (r *rejections) TunnelOpened(context.Context, server.Tunnel)  {}
func (r *rejections) TunnelClosed(context.Context, *server.Closed) {}

func (r *rejections) TunnelRejected(_ context.Context, rej server.Rejection) {
	if rej.Reason == "nonce" {
		r.mu.Lock()
		r.n++
		r.mu.Unlock()
	}
}

func (r *rejections) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

type blocking chan struct{}

func (b blocking) AccessToken(ctx context.Context, _ string) (introspect.Token, error) {
	select {
	case <-b:
	case <-ctx.Done():
	}
	return introspect.Token{}, introspect.ErrUnavailable
}

func (e *env) url() string { return "https://" + e.Addr }

func (e *env) dialer(t *testing.T, http2 bool) *client.Dialer {
	t.Helper()
	d := &client.Dialer{TLSConfig: &tls.Config{RootCAs: e.Roots}, HTTP2: http2}
	t.Cleanup(d.CloseIdleConnections)
	return d
}

func closeConn(t *testing.T, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil {
		t.Log(err)
	}
}

func both(t *testing.T, f func(t *testing.T, http2 bool)) {
	t.Helper()
	for _, http2 := range []bool{false, true} {
		name := "HTTP/1.1"
		if http2 {
			name = "HTTP/2"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			f(t, http2)
		})
	}
}

func echo(t *testing.T, c client.Conn, payload []byte) {
	t.Helper()
	written := make(chan error, 1)
	go func() {
		_, err := c.Write(payload)
		if err == nil {
			err = c.CloseWrite()
		}
		written <- err
	}()
	got, err := io.ReadAll(c)
	if err = errors.Join(err, <-written); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed %d bytes, want %d", len(got), len(payload))
	}
}

func TestDial(t *testing.T) {
	t.Parallel()
	both(t, func(t *testing.T, http2 bool) {
		e := start(t, &relaytest.Options{})
		d := e.dialer(t, http2)
		ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
		c, err := d.Dial(ctx, e.url(), e.Echo.String(), e.AS.Issue(e.Grant(e.Echo)), e.key)
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		defer closeConn(t, c)
		if got := c.RemoteAddr().String(); got != e.Echo.String() && got != e.Addr {
			t.Fatalf("RemoteAddr %s", got)
		}
		if c.LocalAddr() == nil {
			t.Fatal("no LocalAddr")
		}
		echo(t, c, bytes.Repeat([]byte("tunnel"), 50_000))
	})
}

func TestDialSharesHTTP2Connections(t *testing.T) {
	t.Parallel()
	e := start(t, &relaytest.Options{})
	d := e.dialer(t, true)
	var conns []client.Conn
	for range 3 {
		c, err := d.Dial(t.Context(), e.url(), e.Echo.String(), e.AS.Issue(e.Grant(e.Echo)), e.key)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
	}
	for _, c := range conns {
		echo(t, c, []byte("shared"))
		closeConn(t, c)
	}
}

func TestDeadlines(t *testing.T) {
	t.Parallel()
	both(t, func(t *testing.T, http2 bool) {
		e := start(t, &relaytest.Options{})
		c, err := e.dialer(t, http2).Dial(t.Context(), e.url(), e.Echo.String(), e.AS.Issue(e.Grant(e.Echo)), e.key)
		if err != nil {
			t.Fatal(err)
		}
		defer closeConn(t, c)
		err = c.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
		if http2 {
			for _, set := range []func(time.Time) error{c.SetDeadline, c.SetReadDeadline, c.SetWriteDeadline} {
				if derr := set(time.Now()); !errors.Is(derr, os.ErrNoDeadline) {
					t.Fatalf("deadline over HTTP/2 = %v, want os.ErrNoDeadline", derr)
				}
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		var ne net.Error
		if _, err := c.Read(make([]byte, 1)); !errors.As(err, &ne) || !ne.Timeout() {
			t.Fatalf("Read = %v, want a timeout", err)
		}
	})
}

func TestDialAnswersNonceChallenge(t *testing.T) {
	t.Parallel()
	both(t, func(t *testing.T, http2 bool) {
		rec := &rejections{}
		e := start(t, &relaytest.Options{Nonces: true, Observer: rec})
		d := e.dialer(t, http2)
		for range 3 {
			c, err := d.Dial(t.Context(), e.url(), e.Echo.String(), e.AS.Issue(e.Grant(e.Echo)), e.key)
			if err != nil {
				t.Fatal(err)
			}
			echo(t, c, []byte("n"))
			closeConn(t, c)
		}
		if n := rec.count(); n != 1 {
			t.Fatalf("%d nonce challenges for three tunnels; the nonce should be reused", n)
		}
	})
}

func TestDialRefusals(t *testing.T) {
	t.Parallel()
	both(t, func(t *testing.T, http2 bool) {
		e := start(t, &relaytest.Options{Limits: server.Limits{FailedAuthPerMinute: 2}})
		d := e.dialer(t, http2)
		_, err := d.Dial(t.Context(), e.url(), e.Echo.String(), "unknown", e.key)
		var ce *client.Error
		if !errors.As(err, &ce) || ce.StatusCode != http.StatusUnauthorized || ce.AuthError != "invalid_token" || ce.Title != "Unauthorized" {
			t.Fatalf("Dial = %v", err)
		}
		if !strings.Contains(ce.Error(), "401 Unauthorized (invalid_token)") {
			t.Fatalf("Error() = %q", ce.Error())
		}

		other := netip.AddrPortFrom(e.Echo.Addr(), e.Echo.Port()^1)
		_, err = d.Dial(t.Context(), e.url(), other.String(), e.AS.Issue(e.Grant(e.Echo)), e.key)
		if !errors.As(err, &ce) || ce.StatusCode != http.StatusForbidden || ce.AuthError != "" {
			t.Fatalf("Dial = %v", err)
		}
		if strings.Contains(ce.Error(), "(") {
			t.Fatalf("Error() = %q", ce.Error())
		}

		if _, derr := d.Dial(t.Context(), e.url(), e.Echo.String(), "unknown", e.key); derr == nil {
			t.Fatal("accepted")
		}
		_, err = d.Dial(t.Context(), e.url(), e.Echo.String(), e.AS.Issue(e.Grant(e.Echo)), e.key)
		if !errors.As(err, &ce) || ce.StatusCode != http.StatusTooManyRequests || ce.RetryAfter <= 0 {
			t.Fatalf("Dial = %v", err)
		}
	})
}

func TestDialRejectsBadArguments(t *testing.T) {
	t.Parallel()
	e := start(t, &relaytest.Options{})
	d := e.dialer(t, false)
	token := e.AS.Issue(e.Grant(e.Echo))
	for _, relay := range []string{"http://" + e.Addr, "https://", "https://" + e.Addr + "/path", "https://" + e.Addr + "?q", "https://u@" + e.Addr, "https://" + e.Addr + "#f", "::"} {
		if _, err := d.Dial(t.Context(), relay, e.Echo.String(), token, e.key); err == nil {
			t.Errorf("relay URL %q accepted", relay)
		}
	}
	for _, target := range []string{"localhost:22", "10.0.0.1", "[fe80::1%eth0]:22", "10.0.0.1:0"} {
		if _, err := d.Dial(t.Context(), e.url(), target, token, e.key); !errors.Is(err, client.ErrTarget) {
			t.Errorf("target %q: %v", target, err)
		}
	}
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Dial(t.Context(), e.url(), e.Echo.String(), token, edKey); err == nil {
		t.Error("Ed25519 key accepted; it is not on the DPoP allowlist")
	}
	if _, err := client.Dial(t.Context(), e.url(), e.Echo.String(), token, e.key); err == nil {
		t.Error("the default Dialer trusted the test CA")
	}
}

func TestDialHonorsContext(t *testing.T) {
	t.Parallel()
	both(t, func(t *testing.T, http2 bool) {
		e := start(t, &relaytest.Options{})
		d := e.dialer(t, http2)
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := d.Dial(ctx, e.url(), e.Echo.String(), e.AS.Issue(e.Grant(e.Echo)), e.key); err == nil {
			t.Fatal("canceled context ignored")
		}

		ctx, cancel = context.WithCancel(t.Context())
		c, err := d.Dial(ctx, e.url(), e.Echo.String(), e.AS.Issue(e.Grant(e.Echo)), e.key)
		if err != nil {
			t.Fatal(err)
		}
		cancel()
		defer closeConn(t, c)
		echo(t, c, []byte("outlives the dial context"))
	})
}

func TestDialSlowRelayIsCanceled(t *testing.T) {
	t.Parallel()
	both(t, func(t *testing.T, http2 bool) {
		block := make(chan struct{})
		e := start(t, &relaytest.Options{WrapIntrospector: func(server.Introspector) server.Introspector { return blocking(block) }})
		defer close(block)
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		_, err := e.dialer(t, http2).Dial(ctx, e.url(), e.Echo.String(), "token", e.key)
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Dial = %v, want the context's error", err)
		}
	})
}
