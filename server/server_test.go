package server_test

import (
	"bytes"
	"crypto/tls"
	"io"
	"net/http"
	"testing"

	"go.uber.org/goleak"

	"github.com/parallelworks/relay/internal/relaytest"
)

// net/http keeps a connection it closes after a response for a fixed 500 ms, to avoid a TCP reset.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m, goleak.IgnoreAnyFunction("net/http.(*conn).closeWriteAndWait"))
}

func protocols(t *testing.T, f func(t *testing.T, http2 bool)) {
	t.Helper()
	t.Run("HTTP/1.1", func(t *testing.T) {
		t.Parallel()
		f(t, false)
	})
	t.Run("HTTP/2", func(t *testing.T) {
		t.Parallel()
		f(t, true)
	})
}

func TestTunnelEchoes(t *testing.T) {
	t.Parallel()
	protocols(t, func(t *testing.T, http2 bool) {
		e := relaytest.Start(t, &relaytest.Options{})
		token := e.AS.Issue(e.Grant(e.Echo))
		resp, conn := e.Connect(t.Context(), t, e.Echo.String(), token, http2)
		if resp.StatusCode != http.StatusOK || conn == nil {
			t.Fatalf("status %d", resp.StatusCode)
		}
		payload := bytes.Repeat([]byte("relay"), 100_000)
		go func() {
			if _, err := conn.Write(payload); err != nil {
				return
			}
			if err := conn.CloseWrite(); err != nil {
				return
			}
		}()
		got, err := io.ReadAll(conn)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("echoed %d bytes, want %d", len(got), len(payload))
		}
		if err := conn.Close(); err != nil {
			t.Log(err)
		}
	})
}

func TestBytesSentWithTheRequestHeadReachTheTarget(t *testing.T) {
	t.Parallel()
	e := relaytest.Start(t, &relaytest.Options{})
	authority := e.Echo.String()
	h := e.Header(t, authority, e.AS.Issue(e.Grant(e.Echo)), "")
	d := &tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: e.Roots, NextProtos: []string{"http/1.1"}}}
	nc, err := d.DialContext(t.Context(), "tcp", e.Addr)
	if err != nil {
		t.Fatal(err)
	}
	c := nc.(*tls.Conn)
	defer closeLog(t, c)
	var req bytes.Buffer
	req.WriteString("CONNECT " + authority + " HTTP/1.1\r\nHost: " + authority + "\r\n")
	if err := h.Write(&req); err != nil {
		t.Fatal(err)
	}
	req.WriteString("\r\nearly")
	if _, err := c.Write(req.Bytes()); err != nil {
		t.Fatal(err)
	}
	want := "HTTP/1.1 200 OK\r\n\r\nearly"
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
