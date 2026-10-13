package server_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/parallelworks/relay/dpop"
	"github.com/parallelworks/relay/internal/rawconnect"
	"github.com/parallelworks/relay/internal/relaytest"
	"github.com/parallelworks/relay/internal/testpki"
	"github.com/parallelworks/relay/introspect"
	"github.com/parallelworks/relay/server"
)

func drain(t *testing.T, resp *http.Response) {
	t.Helper()
	if _, err := io.Copy(io.Discard, resp.Body); err != nil {
		t.Fatal(err)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatal(err)
	}
}

func closeLog(t *testing.T, c io.Closer) {
	t.Helper()
	if err := c.Close(); err != nil {
		t.Log(err)
	}
}

func expectStatus(t *testing.T, resp *rawconnect.Response, conn rawconnect.Conn, status int) string {
	t.Helper()
	if conn != nil {
		if err := conn.Close(); err != nil {
			t.Log(err)
		}
		t.Fatalf("tunnel opened, want %d", status)
	}
	if resp.StatusCode != status {
		t.Fatalf("status %d, want %d", resp.StatusCode, status)
	}
	return resp.Body
}

func expectChallenge(t *testing.T, resp *rawconnect.Response, authError string) {
	t.Helper()
	want := `DPoP algs="ES256 ES384 PS256"`
	if authError != "" {
		want = `DPoP error="` + authError + `", algs="ES256 ES384 PS256"`
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != want {
		t.Fatalf("WWW-Authenticate %q, want %q", got, want)
	}
}

func TestRejectsMissingCredentialsBeforeIntrospection(t *testing.T) {
	t.Parallel()
	protocols(t, func(t *testing.T, http2 bool) {
		e := relaytest.Start(t, &relaytest.Options{})
		authority := e.Echo.String()
		token := e.AS.Issue(e.Grant(e.Echo))
		full := e.Header(t, authority, token, "")

		resp, conn := e.Raw(t.Context(), t, authority, http.Header{}, http2)
		expectStatus(t, resp, conn, http.StatusUnauthorized)
		expectChallenge(t, resp, "")

		onlyProof := http.Header{dpop.HeaderName: full.Values(dpop.HeaderName)}
		resp, conn = e.Raw(t.Context(), t, authority, onlyProof, http2)
		expectStatus(t, resp, conn, http.StatusUnauthorized)
		expectChallenge(t, resp, "")

		onlyToken := http.Header{"Authorization": full.Values("Authorization")}
		resp, conn = e.Raw(t.Context(), t, authority, onlyToken, http2)
		expectStatus(t, resp, conn, http.StatusUnauthorized)
		expectChallenge(t, resp, "invalid_dpop_proof")

		badProof := e.Header(t, authority, token, "")
		badProof.Set(dpop.HeaderName, "not.a.jws")
		resp, conn = e.Raw(t.Context(), t, authority, badProof, http2)
		expectStatus(t, resp, conn, http.StatusUnauthorized)
		expectChallenge(t, resp, "invalid_dpop_proof")

		for _, bad := range []string{"DPoP", "DPoP ", "DPoP a b", "DPoP a,b", "DPoP =abc", "DPoP abé"} {
			h := e.Header(t, authority, token, "")
			h.Set("Authorization", bad)
			resp, conn = e.Raw(t.Context(), t, authority, h, http2)
			expectStatus(t, resp, conn, http.StatusUnauthorized)
			expectChallenge(t, resp, "invalid_token")
		}

		if n := e.AS.Introspections(); n != 0 {
			t.Fatalf("%d introspections for requests without valid credentials", n)
		}
	})
}

func TestRejectsBearerScheme(t *testing.T) {
	t.Parallel()
	protocols(t, func(t *testing.T, http2 bool) {
		e := relaytest.Start(t, &relaytest.Options{})
		authority := e.Echo.String()
		token := e.AS.Issue(e.Grant(e.Echo))
		for _, scheme := range []string{"Bearer", "bearer", "Basic"} {
			h := e.Header(t, authority, token, "")
			h.Set("Authorization", scheme+" "+token)
			resp, conn := e.Raw(t.Context(), t, authority, h, http2)
			expectStatus(t, resp, conn, http.StatusUnauthorized)
			expectChallenge(t, resp, "invalid_token")
		}
		if n := e.AS.Introspections(); n != 0 {
			t.Fatalf("%d introspections for the Bearer scheme", n)
		}
		h := e.Header(t, authority, token, "")
		h.Set("Authorization", "dpop "+token)
		resp, conn := e.Raw(t.Context(), t, authority, h, http2)
		if resp.StatusCode != http.StatusOK || conn == nil {
			t.Fatalf("the scheme name is case-insensitive (RFC 9110 §11.1), got %d", resp.StatusCode)
		}
		if err := conn.Close(); err != nil {
			t.Log(err)
		}
	})
}

func TestRejectsDuplicateCredentialFields(t *testing.T) {
	t.Parallel()
	protocols(t, func(t *testing.T, http2 bool) {
		e := relaytest.Start(t, &relaytest.Options{})
		authority := e.Echo.String()
		token := e.AS.Issue(e.Grant(e.Echo))
		for _, field := range []string{"Authorization", dpop.HeaderName} {
			h := e.Header(t, authority, token, "")
			h.Add(field, h.Get(field))
			resp, conn := e.Raw(t.Context(), t, authority, h, http2)
			if got := expectStatus(t, resp, conn, http.StatusBadRequest); got != `{"type":"about:blank","title":"Bad Request","status":400}` {
				t.Fatalf("body %s", got)
			}
		}
		if n := e.AS.Introspections(); n != 0 {
			t.Fatalf("%d introspections for duplicated fields", n)
		}
	})
}

func TestRejectsAuthorityTargetMismatch(t *testing.T) {
	t.Parallel()
	protocols(t, func(t *testing.T, http2 bool) {
		e := relaytest.Start(t, &relaytest.Options{})
		other := relaytest.StartEcho(t)
		token := e.AS.Issue(e.Grant(e.Echo))
		resp, conn := e.Connect(t.Context(), t, other.String(), token, http2)
		expectStatus(t, resp, conn, http.StatusForbidden)
		if !strings.Contains(e.Logs.String(), `"reason":"target_mismatch"`) {
			t.Fatal("mismatch not logged")
		}
	})
}

func TestRejectsTargetsOutsideEgressPolicy(t *testing.T) {
	t.Parallel()
	protocols(t, func(t *testing.T, http2 bool) {
		e := relaytest.Start(t, &relaytest.Options{})
		for _, target := range []string{"127.0.0.2:22", "10.0.0.1:22", "[::1]:22"} {
			ap := netip.MustParseAddrPort(target)
			token := e.AS.Issue(e.Grant(ap))
			resp, conn := e.Connect(t.Context(), t, target, token, http2)
			expectStatus(t, resp, conn, http.StatusForbidden)
		}
	})
}

func TestRejectsMalformedRequests(t *testing.T) {
	t.Parallel()
	e := relaytest.Start(t, &relaytest.Options{})
	token := e.AS.Issue(e.Grant(e.Echo))
	cases := []struct{ name, authority string }{
		{"host name", "localhost:22"},
		{"no port", "127.0.0.1"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			protocols(t, func(t *testing.T, http2 bool) {
				resp, conn := e.Raw(t.Context(), t, c.authority, e.Header(t, c.authority, token, ""), http2)
				expectStatus(t, resp, conn, http.StatusBadRequest)
			})
		})
	}
	t.Run("not CONNECT", func(t *testing.T) {
		protocols(t, func(t *testing.T, http2 bool) {
			hc := client(e, http2)
			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+e.Addr+"/", http.NoBody)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := hc.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status %d", resp.StatusCode)
			}
			drain(t, resp)
			hc.CloseIdleConnections()
		})
	})
	t.Run("path in HTTP/1.1 request target", func(t *testing.T) {
		if status := rawHTTP1(t, e, "CONNECT /x HTTP/1.1\r\nHost: "+e.Echo.String()+"\r\n\r\n"); status != http.StatusBadRequest {
			t.Fatalf("status %d", status)
		}
	})
	t.Run("zoned address", func(t *testing.T) {
		if status := rawHTTP1(t, e, "CONNECT [fe80::1%25eth0]:22 HTTP/1.1\r\nHost: [fe80::1%25eth0]:22\r\n\r\n"); status != http.StatusBadRequest {
			t.Fatalf("status %d", status)
		}
	})
}

func client(e *relaytest.Env, http2 bool) *http.Client {
	protocols := new(http.Protocols)
	if http2 {
		protocols.SetHTTP2(true)
	} else {
		protocols.SetHTTP1(true)
	}
	return &http.Client{Transport: &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: e.Roots},
		Protocols:       protocols,
	}}
}

func dialTLS(t *testing.T, e *relaytest.Env, proto string) *tls.Conn {
	t.Helper()
	d := &tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: e.Roots, NextProtos: []string{proto}}}
	c, err := d.DialContext(t.Context(), "tcp", e.Addr)
	if err != nil {
		t.Fatal(err)
	}
	return c.(*tls.Conn)
}

func rawHTTP1(t *testing.T, e *relaytest.Env, request string) int {
	t.Helper()
	c := dialTLS(t, e, "http/1.1")
	defer closeLog(t, c)
	if _, err := io.WriteString(c, request); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	drain(t, resp)
	return resp.StatusCode
}

func TestReadHeaderTimeout(t *testing.T) {
	t.Parallel()
	e := relaytest.Start(t, &relaytest.Options{Limits: server.Limits{ReadHeaderTimeout: 100 * time.Millisecond}})
	c := dialTLS(t, e, "http/1.1")
	defer closeLog(t, c)
	if _, err := io.WriteString(c, "CONNECT "+e.Echo.String()+" HTTP/1.1\r\n"); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := c.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, c); err != nil {
		t.Fatalf("connection not closed by the server: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("slow header held the connection for %v", elapsed)
	}
}

func TestMaxHeaderBytes(t *testing.T) {
	t.Parallel()
	e := relaytest.Start(t, &relaytest.Options{})
	token := e.AS.Issue(e.Grant(e.Echo))
	protocols(t, func(t *testing.T, http2 bool) {
		h := e.Header(t, e.Echo.String(), token, "")
		h.Set("X-Padding", strings.Repeat("a", 2*server.MaxHeaderBytes))
		resp, conn, err := rawconnect.Do(t.Context(), &rawconnect.Request{
			Addr: e.Addr, Roots: e.Roots, Authority: e.Echo.String(), Header: h, HTTP2: http2,
		})
		if conn != nil {
			t.Fatal("oversized header opened a tunnel")
		}
		if err == nil && resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
			t.Fatalf("status %d", resp.StatusCode)
		}
	})
	if n := e.AS.Introspections(); n != 0 {
		t.Fatalf("%d introspections for oversized headers", n)
	}
}

func TestPerSourceConnectionLimit(t *testing.T) {
	t.Parallel()
	t.Run("connections", func(t *testing.T) {
		t.Parallel()
		e := relaytest.Start(t, &relaytest.Options{Limits: server.Limits{MaxConnsPerSource: 1}})
		first := dialTLS(t, e, "http/1.1")
		d := &tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: e.Roots}}
		if c, err := d.DialContext(t.Context(), "tcp", e.Addr); err == nil {
			closeLog(t, c)
			t.Fatal("second connection from the same source completed a handshake")
		}
		if err := first.Close(); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(10 * time.Second)
		for {
			c, err := d.DialContext(t.Context(), "tcp", e.Addr)
			if err == nil {
				closeLog(t, c)
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("slot not released after the first connection closed: %v", err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
	t.Run("tunnels", func(t *testing.T) {
		t.Parallel()
		e := relaytest.Start(t, &relaytest.Options{Limits: server.Limits{MaxTunnelsPerSource: 1}})
		resp, open := e.Connect(t.Context(), t, e.Echo.String(), e.AS.Issue(e.Grant(e.Echo)), true)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		resp, conn := e.Connect(t.Context(), t, e.Echo.String(), e.AS.Issue(e.Grant(e.Echo)), true)
		expectStatus(t, resp, conn, http.StatusTooManyRequests)
		if resp.Header.Get("Retry-After") == "" {
			t.Fatal("no Retry-After")
		}
		if err := open.Close(); err != nil {
			t.Log(err)
		}
	})
}

func TestTotalConnectionLimit(t *testing.T) {
	t.Parallel()
	protocols(t, func(t *testing.T, http2 bool) {
		e := relaytest.Start(t, &relaytest.Options{Limits: server.Limits{MaxTunnels: 1}})
		resp, open := e.Connect(t.Context(), t, e.Echo.String(), e.AS.Issue(e.Grant(e.Echo)), http2)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if n := e.Server.Tunnels(); n != 1 {
			t.Fatalf("Tunnels() = %d", n)
		}
		resp, conn := e.Connect(t.Context(), t, e.Echo.String(), e.AS.Issue(e.Grant(e.Echo)), http2)
		expectStatus(t, resp, conn, http.StatusServiceUnavailable)
		if resp.Header.Get("Retry-After") != "1" {
			t.Fatalf("Retry-After %q", resp.Header.Get("Retry-After"))
		}
		if err := open.Close(); err != nil {
			t.Log(err)
		}
	})
}

func TestFailedAuthenticationRateLimit(t *testing.T) {
	t.Parallel()
	protocols(t, func(t *testing.T, http2 bool) {
		e := relaytest.Start(t, &relaytest.Options{Limits: server.Limits{FailedAuthPerMinute: 3}})
		authority := e.Echo.String()
		for range 3 {
			h := e.Header(t, authority, "guess", "")
			resp, conn := e.Raw(t.Context(), t, authority, h, http2)
			expectStatus(t, resp, conn, http.StatusUnauthorized)
		}
		introspections := e.AS.Introspections()
		resp, conn := e.Connect(t.Context(), t, authority, e.AS.Issue(e.Grant(e.Echo)), http2)
		expectStatus(t, resp, conn, http.StatusTooManyRequests)
		wait, err := strconv.Atoi(resp.Header.Get("Retry-After"))
		if err != nil || wait < 1 || wait > 20 {
			t.Fatalf("Retry-After %q", resp.Header.Get("Retry-After"))
		}
		if e.AS.Introspections() != introspections {
			t.Fatal("a rate-limited request was introspected")
		}
	})
}

func TestNonceChallengeDoesNotCountAsFailure(t *testing.T) {
	t.Parallel()
	protocols(t, func(t *testing.T, http2 bool) {
		e := relaytest.Start(t, &relaytest.Options{Nonces: true, Limits: server.Limits{FailedAuthPerMinute: 1}})
		authority := e.Echo.String()
		for range 3 {
			token := e.AS.Issue(e.Grant(e.Echo))
			resp, conn := e.Raw(t.Context(), t, authority, e.Header(t, authority, token, ""), http2)
			expectStatus(t, resp, conn, http.StatusUnauthorized)
			expectChallenge(t, resp, "use_dpop_nonce")
			nonce := resp.Header.Get(dpop.NonceHeaderName)
			if nonce == "" {
				t.Fatal("no DPoP-Nonce")
			}
			resp, conn = e.Raw(t.Context(), t, authority, e.Header(t, authority, token, nonce), http2)
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status %d with the issued nonce", resp.StatusCode)
			}
			if err := conn.Close(); err != nil {
				t.Log(err)
			}
		}
	})
}

func TestErrorBodiesOmitReason(t *testing.T) {
	t.Parallel()
	protocols(t, func(t *testing.T, http2 bool) {
		e := relaytest.Start(t, &relaytest.Options{})
		authority := e.Echo.String()
		unauthorized := `{"type":"about:blank","title":"Unauthorized","status":401}`

		wrongKey := e.Grant(e.Echo)
		wrongKey.JKT = "another-key"
		expired := e.Grant(e.Echo)
		expired.Override = map[string]any{"active": false}
		used := e.AS.Issue(e.Grant(e.Echo))
		resp, conn := e.Connect(t.Context(), t, authority, used, http2)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if err := conn.Close(); err != nil {
			t.Log(err)
		}

		cases := map[string]string{
			"key_binding":    e.AS.Issue(wrongKey),
			"inactive_token": e.AS.Issue(expired),
			"proof":          "",
		}
		for reason, token := range cases {
			var h http.Header
			if token == "" {
				h = e.Header(t, authority, used, "")
				h.Set(dpop.HeaderName, h.Get(dpop.HeaderName)+"x")
			} else {
				h = e.Header(t, authority, token, "")
			}
			refused, opened := e.Raw(t.Context(), t, authority, h, http2)
			if got := expectStatus(t, refused, opened, http.StatusUnauthorized); got != unauthorized {
				t.Fatalf("%s: body %s", reason, got)
			}
			if refused.Header.Get("Content-Type") != "application/problem+json" {
				t.Fatalf("Content-Type %q", refused.Header.Get("Content-Type"))
			}
			if !strings.Contains(e.Logs.String(), `"reason":"`+reason+`"`) {
				t.Fatalf("reason %s not logged", reason)
			}
		}
		resp, conn = e.Connect(t.Context(), t, authority, used, http2)
		if got := expectStatus(t, resp, conn, http.StatusUnauthorized); got != unauthorized {
			t.Fatalf("reused token: body %s", got)
		}
		if strings.Contains(e.Logs.String(), used) {
			t.Fatal("a token appears in the log")
		}
	})
}

func TestRejectsTLS12(t *testing.T) {
	t.Parallel()
	e := relaytest.Start(t, &relaytest.Options{})
	//nolint:gosec // G402: the test checks that the relay refuses TLS 1.2.
	d := &tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, RootCAs: e.Roots}}
	if c, err := d.DialContext(t.Context(), "tcp", e.Addr); err == nil {
		closeLog(t, c)
		t.Fatal("TLS 1.2 handshake succeeded")
	}
	c := dialTLS(t, e, "h2")
	defer closeLog(t, c)
	state := c.ConnectionState()
	if state.Version != tls.VersionTLS13 || state.NegotiatedProtocol != "h2" {
		t.Fatalf("version %x, ALPN %q", state.Version, state.NegotiatedProtocol)
	}
	c11 := dialTLS(t, e, "http/1.1")
	defer closeLog(t, c11)
	if p := c11.ConnectionState().NegotiatedProtocol; p != "http/1.1" {
		t.Fatalf("ALPN %q", p)
	}
}

func TestReloadsCertificateWithoutRestart(t *testing.T) {
	t.Parallel()
	e := relaytest.Start(t, &relaytest.Options{})
	oldRoots := e.Roots
	before := dialTLS(t, e, "http/1.1")
	defer closeLog(t, before)

	e.CA = testpki.New(t)
	e.WriteCertificate(t)
	changed, err := e.Certs.Reload()
	if err != nil || !changed {
		t.Fatalf("Reload = %v, %v", changed, err)
	}
	e.Roots = e.CA.Pool()
	after := dialTLS(t, e, "http/1.1")
	defer closeLog(t, after)
	d := &tls.Dialer{Config: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: oldRoots}}
	if c, err := d.DialContext(t.Context(), "tcp", e.Addr); err == nil {
		closeLog(t, c)
		t.Fatal("the old certificate is still served")
	}
	if changed, err := e.Certs.Reload(); err != nil || changed {
		t.Fatalf("Reload of unchanged files = %v, %v", changed, err)
	}
}

func TestIntrospectionFailures(t *testing.T) {
	t.Parallel()
	protocols(t, func(t *testing.T, http2 bool) {
		e := relaytest.Start(t, &relaytest.Options{})
		token := e.AS.Issue(e.Grant(e.Echo))
		e.AS.Handle(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusInternalServerError) })
		resp, conn := e.Connect(t.Context(), t, e.Echo.String(), token, http2)
		expectStatus(t, resp, conn, http.StatusServiceUnavailable)
		if resp.Header.Get("Retry-After") != "5" {
			t.Fatalf("Retry-After %q", resp.Header.Get("Retry-After"))
		}
	})
}

type slowIntrospector struct{}

func (slowIntrospector) AccessToken(ctx context.Context, _ string) (introspect.Token, error) {
	<-ctx.Done()
	return introspect.Token{}, ctx.Err()
}

func TestIntrospectionTimeout(t *testing.T) {
	t.Parallel()
	e := relaytest.Start(t, &relaytest.Options{
		Introspector: slowIntrospector{},
		Limits:       server.Limits{IntrospectionTimeout: 50 * time.Millisecond},
	})
	resp, conn := e.Connect(t.Context(), t, e.Echo.String(), "token", false)
	expectStatus(t, resp, conn, http.StatusServiceUnavailable)
}

func TestReplayCacheFull(t *testing.T) {
	t.Parallel()
	e := relaytest.Start(t, &relaytest.Options{MaxReplayEntries: 1})
	authority := e.Echo.String()
	resp, open := e.Connect(t.Context(), t, authority, e.AS.Issue(e.Grant(e.Echo)), false)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	resp, conn := e.Connect(t.Context(), t, authority, e.AS.Issue(e.Grant(e.Echo)), false)
	expectStatus(t, resp, conn, http.StatusServiceUnavailable)
	if err := open.Close(); err != nil {
		t.Log(err)
	}
}

func TestUnreachableTarget(t *testing.T) {
	t.Parallel()
	e := relaytest.Start(t, &relaytest.Options{})
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := netip.MustParseAddrPort(ln.Addr().String())
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	protocols(t, func(t *testing.T, http2 bool) {
		resp, conn := e.Connect(t.Context(), t, closed.String(), e.AS.Issue(e.Grant(closed)), http2)
		if got := expectStatus(t, resp, conn, http.StatusBadGateway); got != `{"type":"about:blank","title":"Bad Gateway","status":502}` {
			t.Fatalf("body %s", got)
		}
	})
}
