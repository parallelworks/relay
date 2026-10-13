package rawconnect_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"strconv"
	"sync"
	"testing"
	"time"

	"go.uber.org/goleak"

	"github.com/parallelworks/relay/internal/rawconnect"
	"github.com/parallelworks/relay/internal/relaytest"
	"github.com/parallelworks/relay/internal/testpki"
)

// net/http keeps a connection it closes after a response for a fixed 500 ms, to avoid a TCP reset.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m, goleak.IgnoreAnyFunction("net/http.(*conn).closeWriteAndWait"))
}

func TestDo(t *testing.T) {
	t.Parallel()
	e := relaytest.Start(t, &relaytest.Options{})
	for _, http2 := range []bool{false, true} {
		t.Run(strconv.FormatBool(http2), func(t *testing.T) { roundTrip(t, e, http2) })
	}
}

func roundTrip(t *testing.T, e *relaytest.Env, http2 bool) {
	authority := e.Echo.String()
	token := e.AS.Issue(e.Grant(e.Echo))
	req := &rawconnect.Request{Addr: e.Addr, Roots: e.Roots, Authority: authority, Header: e.Header(t, authority, token, ""), HTTP2: http2}
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	resp, conn, err := rawconnect.Do(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || resp.Body != "" {
		t.Fatalf("response %+v", resp)
	}
	if _, werr := conn.Write([]byte("abc")); werr != nil {
		t.Fatal(werr)
	}
	if cerr := conn.CloseWrite(); cerr != nil {
		t.Fatal(cerr)
	}
	got, err := io.ReadAll(conn)
	if err != nil || !bytes.Equal(got, []byte("abc")) {
		t.Fatalf("echo %q, %v", got, err)
	}
	if cerr := conn.Close(); cerr != nil {
		t.Log(cerr)
	}

	req.Header = http.Header{}
	resp, conn, err = rawconnect.Do(t.Context(), req)
	if err != nil || conn != nil {
		t.Fatalf("Do = %v, %v", conn, err)
	}
	if resp.StatusCode != http.StatusUnauthorized || resp.Body == "" {
		t.Fatalf("response %+v", resp)
	}
}

func TestDoErrors(t *testing.T) {
	t.Parallel()
	e := relaytest.Start(t, &relaytest.Options{})
	for _, http2 := range []bool{false, true} {
		if _, _, err := rawconnect.Do(t.Context(), &rawconnect.Request{Addr: e.Addr, Authority: "x", HTTP2: http2}); err == nil {
			t.Fatal("untrusted relay accepted")
		}
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		if _, _, err := rawconnect.Do(ctx, &rawconnect.Request{Addr: e.Addr, Roots: e.Roots, Authority: "x", HTTP2: http2}); err == nil {
			t.Fatal("canceled context ignored")
		}
	}
	if _, _, err := rawconnect.Do(t.Context(), &rawconnect.Request{Addr: "127.0.0.1:1", HTTP2: true, Authority: "a b"}); err == nil {
		t.Fatal("unreachable relay accepted")
	}
}

func TestDoWhenTheServerHangsUp(t *testing.T) {
	t.Parallel()
	ca := testpki.New(t)
	ln, err := tls.Listen("tcp", "127.0.0.1:0", ca.ServerConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			tc := c.(*tls.Conn)
			if herr := tc.HandshakeContext(t.Context()); herr != nil {
				t.Log(herr)
			}
			if cerr := tc.Close(); cerr != nil {
				t.Log(cerr)
			}
		}
	})
	defer func() {
		if cerr := ln.Close(); cerr != nil {
			t.Error(cerr)
		}
		wg.Wait()
	}()
	_, _, err = rawconnect.Do(t.Context(), &rawconnect.Request{Addr: ln.Addr().String(), Roots: ca.Pool(), Authority: "10.0.0.1:22", Header: http.Header{}})
	if err == nil {
		t.Fatal("no error when the server hung up")
	}
}
