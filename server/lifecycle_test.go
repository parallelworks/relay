package server_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/parallelworks/relay/internal/rawconnect"
	"github.com/parallelworks/relay/internal/relaytest"
	"github.com/parallelworks/relay/server"
)

type recorder struct {
	mu       sync.Mutex
	opened   []server.Tunnel
	closed   []server.Closed
	rejected []server.Rejection
	done     chan server.Closed
}

func newRecorder() *recorder { return &recorder{done: make(chan server.Closed, 16)} }

func (r *recorder) TunnelOpened(_ context.Context, t server.Tunnel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.opened = append(r.opened, t)
}

func (r *recorder) TunnelClosed(_ context.Context, c *server.Closed) {
	r.mu.Lock()
	r.closed = append(r.closed, *c)
	r.mu.Unlock()
	r.done <- *c
}

func (r *recorder) TunnelRejected(_ context.Context, rej server.Rejection) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rejected = append(r.rejected, rej)
}

func waitClosed(t *testing.T, r *recorder) server.Closed {
	t.Helper()
	select {
	case c := <-r.done:
		return c
	case <-time.After(10 * time.Second):
		t.Fatal("tunnel did not close")
		return server.Closed{}
	}
}

func TestRevocationClosesTunnel(t *testing.T) {
	t.Parallel()
	protocols(t, func(t *testing.T, http2 bool) {
		rec := newRecorder()
		e := relaytest.Start(t, &relaytest.Options{Observer: rec, SessionInterval: 20 * time.Millisecond})
		g := e.Grant(e.Echo)
		resp, conn := e.Connect(t.Context(), t, e.Echo.String(), e.AS.Issue(g), http2)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		defer closeLog(t, conn)
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatal(err)
		}
		e.AS.SetSession(g.Session, g.Subject, false)
		c := waitClosed(t, rec)
		if c.Reason != server.CloseRevoked || c.Subject != "alice" || c.Target != e.Echo || c.Upstream != 4 || c.Downstream != 4 {
			t.Fatalf("closed %+v", c)
		}
		if _, err := io.Copy(io.Discard, conn); err == nil && http2 {
			t.Fatal("HTTP/2 stream ended cleanly after revocation")
		}
		if e.Sessions.Open() != 0 {
			t.Fatal("session still registered")
		}
	})
}

func TestIdleTunnelCloses(t *testing.T) {
	t.Parallel()
	rec := newRecorder()
	e := relaytest.Start(t, &relaytest.Options{Observer: rec, Limits: server.Limits{IdleTimeout: 50 * time.Millisecond}})
	resp, conn := e.Connect(t.Context(), t, e.Echo.String(), e.AS.Issue(e.Grant(e.Echo)), false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	defer closeLog(t, conn)
	if c := waitClosed(t, rec); c.Reason != server.CloseIdle {
		t.Fatalf("reason %q", c.Reason)
	}
}

func TestShutdownWaitsThenClosesTunnels(t *testing.T) {
	t.Parallel()
	protocols(t, func(t *testing.T, http2 bool) {
		rec := newRecorder()
		e := relaytest.Start(t, &relaytest.Options{Observer: rec})
		resp, conn := e.Connect(t.Context(), t, e.Echo.String(), e.AS.Issue(e.Grant(e.Echo)), http2)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		defer closeLog(t, conn)
		ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
		defer cancel()
		if err := e.Server.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Shutdown = %v", err)
		}
		if c := waitClosed(t, rec); c.Reason != server.CloseShutdown {
			t.Fatalf("reason %q", c.Reason)
		}
		if _, conn2, err := doConnect(t, e, http2); err == nil && conn2 != nil {
			closeLog(t, conn2)
			t.Fatal("tunnel opened after shutdown")
		}
	})
}

func TestShutdownAfterTunnelsEnd(t *testing.T) {
	t.Parallel()
	e := relaytest.Start(t, &relaytest.Options{})
	resp, conn := e.Connect(t.Context(), t, e.Echo.String(), e.AS.Issue(e.Grant(e.Echo)), true)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	defer closeLog(t, conn)
	drained := make(chan error, 1)
	go func() {
		time.Sleep(50 * time.Millisecond)
		err := conn.CloseWrite()
		if err == nil {
			_, err = io.Copy(io.Discard, conn)
		}
		drained <- err
	}()
	if err := e.Server.Shutdown(t.Context()); err != nil {
		t.Fatalf("Shutdown = %v", err)
	}
	if err := <-drained; err != nil {
		t.Fatal(err)
	}
}

func TestObserverSeesEveryTunnel(t *testing.T) {
	t.Parallel()
	rec := newRecorder()
	e := relaytest.Start(t, &relaytest.Options{Observer: rec})
	resp, conn := e.Connect(t.Context(), t, e.Echo.String(), e.AS.Issue(e.Grant(e.Echo)), false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Log(err)
	}
	c := waitClosed(t, rec)
	resp, conn = e.Connect(t.Context(), t, e.Echo.String(), "unknown", false)
	expectStatus(t, resp, conn, http.StatusUnauthorized)

	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.opened) != 1 || rec.opened[0].Protocol != "HTTP/1.1" || rec.opened[0].ID != c.ID {
		t.Fatalf("opened %+v", rec.opened)
	}
	if c.Reason != server.CloseEOF || c.Duration <= 0 {
		t.Fatalf("closed %+v", c)
	}
	if len(rec.rejected) != 1 || rec.rejected[0] != (server.Rejection{Status: http.StatusUnauthorized, Reason: "inactive_token"}) {
		t.Fatalf("rejected %+v", rec.rejected)
	}
}

func doConnect(t *testing.T, e *relaytest.Env, http2 bool) (*rawconnect.Response, rawconnect.Conn, error) {
	t.Helper()
	return rawconnect.Do(t.Context(), &rawconnect.Request{
		Addr:      e.Addr,
		Roots:     e.Roots,
		Authority: e.Echo.String(),
		Header:    e.Header(t, e.Echo.String(), e.AS.Issue(e.Grant(e.Echo)), ""),
		HTTP2:     http2,
	})
}
