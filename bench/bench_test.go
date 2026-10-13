// Package bench measures the relay against a WebSocket tunnel baseline. It is a separate module so
// the relay's own module never contains WebSocket code; WebSocket's handshake needs SHA-1, so this
// module never runs with GODEBUG=fips140=only.
package bench

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"go.uber.org/goleak"

	"github.com/parallelworks/relay/client"
	"github.com/parallelworks/relay/internal/relaytest"
	"github.com/parallelworks/relay/internal/testpki"
)

const chunk = 256 << 10

// net/http keeps a connection it closes after a response for a fixed 500 ms, to avoid a TCP reset.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m, goleak.IgnoreAnyFunction("net/http.(*conn).closeWriteAndWait"))
}

func must(tb testing.TB, err error) {
	tb.Helper()
	if err != nil {
		tb.Fatal(err)
	}
}

// startSink runs a TCP server on 127.0.0.1 that discards what it reads.
func startSink(tb testing.TB) netip.AddrPort {
	tb.Helper()
	ln, err := (&net.ListenConfig{}).Listen(tb.Context(), "tcp", "127.0.0.1:0")
	must(tb, err)
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			wg.Go(func() {
				_, cerr := io.Copy(io.Discard, c)
				if cerr = errors.Join(cerr, c.Close()); cerr != nil {
					tb.Log("sink:", cerr)
				}
			})
		}
	})
	tb.Cleanup(func() {
		must(tb, ln.Close())
		wg.Wait()
	})
	return netip.MustParseAddrPort(ln.Addr().String())
}

type transport struct {
	name string
	dial func(tb testing.TB, target netip.AddrPort) net.Conn
}

func relayTransport(tb testing.TB, http2 bool) func(testing.TB, netip.AddrPort) net.Conn {
	e := relaytest.Start(tb, &relaytest.Options{})
	d := &client.Dialer{TLSConfig: &tls.Config{RootCAs: e.Roots}, HTTP2: http2}
	tb.Cleanup(d.CloseIdleConnections)
	return func(tb testing.TB, target netip.AddrPort) net.Conn {
		c, err := d.Dial(tb.Context(), "https://"+e.Addr, target.String(), e.AS.Issue(e.Grant(target)), e.Key)
		must(tb, err)
		return c
	}
}

// websocketTransport is a WebSocket tunnel over TLS 1.3: one binary message stream per tunnel, the
// shape a CONNECT tunnel replaces. It does no authorization, which only favors it.
func websocketTransport(tb testing.TB) func(testing.TB, netip.AddrPort) net.Conn {
	ca := testpki.New(tb)
	tunnels := &wsTunnels{}
	srv := &http.Server{
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         ca.ServerConfig(tb),
		Handler:           tunnels,
	}
	ln, err := (&net.ListenConfig{}).Listen(tb.Context(), "tcp", "127.0.0.1:0")
	must(tb, err)
	served := make(chan error, 1)
	go func() { served <- srv.ServeTLS(ln, "", "") }()
	tb.Cleanup(func() {
		must(tb, srv.Close())
		if err := <-served; !errors.Is(err, http.ErrServerClosed) {
			tb.Error(err)
		}
		tunnels.mu.Lock()
		defer tunnels.mu.Unlock()
		if err := errors.Join(tunnels.errs...); err != nil {
			tb.Log("websocket tunnels:", err)
		}
	})
	hc := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: ca.Pool()}}}
	tb.Cleanup(hc.CloseIdleConnections)
	addr := ln.Addr().String()
	return func(tb testing.TB, target netip.AddrPort) net.Conn {
		ws, _, err := websocket.Dial(tb.Context(), "wss://"+addr+"/?target="+target.String(), &websocket.DialOptions{HTTPClient: hc}) //nolint:bodyclose // The library closes the handshake response.
		must(tb, err)
		return websocket.NetConn(context.WithoutCancel(tb.Context()), ws, websocket.MessageBinary)
	}
}

func transports(b *testing.B) []transport {
	return []transport{
		{"connect-h1", relayTransport(b, false)},
		{"connect-h2", relayTransport(b, true)},
		{"websocket", websocketTransport(b)},
	}
}

type wsTunnels struct {
	mu   sync.Mutex
	errs []error
}

func (t *wsTunnels) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := t.serve(w, r); err != nil {
		t.mu.Lock()
		t.errs = append(t.errs, err)
		t.mu.Unlock()
	}
}

func (t *wsTunnels) serve(w http.ResponseWriter, r *http.Request) error {
	ws, err := websocket.Accept(w, r, nil)
	if err != nil {
		return err
	}
	ws.SetReadLimit(-1)
	wsConn := websocket.NetConn(r.Context(), ws, websocket.MessageBinary)
	tc, err := (&net.Dialer{}).DialContext(r.Context(), "tcp", r.URL.Query().Get("target"))
	if err != nil {
		return errors.Join(err, ws.Close(websocket.StatusInternalError, "dial failed"))
	}
	downstream := make(chan error, 1)
	go func() {
		_, cerr := io.Copy(wsConn, tc)
		downstream <- cerr
	}()
	_, err = io.Copy(tc, wsConn)
	return errors.Join(err, tc.Close(), <-downstream, wsConn.Close())
}

// BenchmarkThroughput writes to a discarding target through one or 64 tunnels at once.
func BenchmarkThroughput(b *testing.B) {
	sink := startSink(b)
	payload := make([]byte, chunk)
	for _, tr := range transports(b) {
		for _, tunnels := range []int{1, 64} {
			b.Run(fmt.Sprintf("transport=%s/tunnels=%d", tr.name, tunnels), func(b *testing.B) {
				conns := make([]net.Conn, tunnels)
				for i := range conns {
					conns[i] = tr.dial(b, sink)
				}
				b.SetBytes(int64(chunk * tunnels))
				b.ResetTimer()
				for b.Loop() {
					var wg sync.WaitGroup
					errs := make([]error, tunnels)
					for i, c := range conns {
						wg.Go(func() { _, errs[i] = c.Write(payload) })
					}
					wg.Wait()
					must(b, errors.Join(errs...))
				}
				b.StopTimer()
				for _, c := range conns {
					must(b, c.Close())
				}
			})
		}
	}
}

// BenchmarkConnectLatency opens a tunnel, with the authorization server in-process, and waits for
// the first byte back from an echo target.
func BenchmarkConnectLatency(b *testing.B) {
	for _, tr := range transports(b) {
		echo := relaytest.StartEcho(b)
		b.Run("transport="+tr.name, func(b *testing.B) {
			buf := make([]byte, 1)
			for b.Loop() {
				c := tr.dial(b, echo)
				_, err := c.Write(buf)
				if err == nil {
					_, err = io.ReadFull(c, buf)
				}
				must(b, errors.Join(err, c.Close()))
			}
		})
	}
}
