package server_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/parallelworks/relay/internal/relaytest"
	"github.com/parallelworks/relay/server"
)

func records(t *testing.T, logs, msg string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for line := range strings.Lines(logs) {
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

func expectFields(t *testing.T, rec, want map[string]any) {
	t.Helper()
	if ts, ok := rec["time"].(string); !ok {
		t.Errorf("%s has no time", rec["msg"])
	} else if _, err := time.Parse(time.RFC3339Nano, ts); err != nil {
		t.Errorf("%s time %q: %v", rec["msg"], ts, err)
	}
	source, _ := rec["source"].(string)
	if ap, err := netip.ParseAddrPort(source); err != nil || !ap.Addr().IsLoopback() || ap.Port() == 0 {
		t.Errorf("%s source %q", rec["msg"], source)
	}
	for k, v := range want {
		if rec[k] != v {
			t.Errorf("%s %s = %v, want %v", rec["msg"], k, rec[k], v)
		}
	}
}

// TestAuditRecords checks that every opened, closed and refused tunnel leaves a record of when,
// from where, by whom, with which token, to what, and with what outcome (AU-3).
func TestAuditRecords(t *testing.T) {
	t.Parallel()
	protocols(t, func(t *testing.T, http2 bool) {
		rec := newRecorder()
		e := relaytest.Start(t, &relaytest.Options{Observer: rec})
		g := e.Grant(e.Echo)
		token := e.AS.Issue(g)
		resp, conn := e.Connect(t.Context(), t, e.Echo.String(), token, http2)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if _, err := conn.Write([]byte("ping")); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Fatal(err)
		}
		waitClosed(t, rec)

		other := relaytest.StartEcho(t)
		second := e.AS.Issue(e.Grant(e.Echo))
		resp, conn = e.Connect(t.Context(), t, other.String(), second, http2)
		expectStatus(t, resp, conn, http.StatusForbidden)

		proto := "HTTP/1.1"
		if http2 {
			proto = "HTTP/2.0"
		}
		tunnel := map[string]any{
			"sub":      "alice",
			"session":  g.Session,
			"token_id": server.TokenID(token),
			"target":   e.Echo.String(),
			"protocol": proto,
		}
		logs := e.Logs.String()
		opened, closed := records(t, logs, "tunnel.opened"), records(t, logs, "tunnel.closed")
		if len(opened) != 1 || len(closed) != 1 {
			t.Fatalf("%d opened and %d closed records:\n%s", len(opened), len(closed), logs)
		}
		expectFields(t, opened[0], tunnel)
		expectFields(t, closed[0], tunnel)
		if opened[0]["tunnel"] != closed[0]["tunnel"] {
			t.Errorf("tunnel ids %v and %v", opened[0]["tunnel"], closed[0]["tunnel"])
		}
		if bytes, _ := closed[0]["bytes"].(map[string]any); bytes["upstream"] != 4.0 || bytes["downstream"] != 4.0 {
			t.Errorf("bytes %v", closed[0]["bytes"])
		}
		if closed[0]["close_reason"] == nil || closed[0]["duration"] == nil {
			t.Errorf("closed %v", closed[0])
		}

		rejected := records(t, logs, "tunnel.rejected")
		if len(rejected) != 1 {
			t.Fatalf("%d rejected records:\n%s", len(rejected), logs)
		}
		expectFields(t, rejected[0], map[string]any{
			"status":    float64(http.StatusForbidden),
			"reason":    "target_mismatch",
			"authority": other.String(),
			"token_id":  server.TokenID(second),
		})
	})
}
