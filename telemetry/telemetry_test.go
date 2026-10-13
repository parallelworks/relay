package telemetry

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/goleak"

	"github.com/parallelworks/relay/server"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

type stringer struct{ s string }

func (s stringer) String() string { return s.s }

func TestRedactsTokens(t *testing.T) {
	t.Parallel()
	const (
		jwt    = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl"
		opaque = "QWERTYUIOPASDFGHJKLZXCVBNM"
	)
	var buf bytes.Buffer
	logger := slog.New(NewLogHandler(&buf, slog.LevelDebug)).With(slog.String("access_token", opaque), slog.String("client_id", "relay-1"))
	logger.Info("request with Authorization: DPoP "+opaque,
		slog.String("proof", jwt),
		slog.String("header", "Authorization: Bearer "+opaque),
		slog.Any("error", errors.New("introspection of "+jwt+" failed")),
		slog.Any("value", stringer{"bearer " + opaque}),
		slog.Any("unknown", struct{ Token string }{opaque}),
		slog.Group("request", slog.String("dpop", jwt), slog.String("note", "inner "+jwt)),
		slog.String("token_id", "3c469e9d"),
		slog.Int("status", 401),
		slog.String("target", "10.0.0.1:22"),
	)
	out := buf.String()
	for _, secret := range []string{jwt, opaque, "eyJ"} {
		if strings.Contains(out, secret) {
			t.Fatalf("log carries %q:\n%s", secret, out)
		}
	}
	for _, kept := range []string{`"client_id":"relay-1"`, `"token_id":"3c469e9d"`, `"status":401`, `"target":"10.0.0.1:22"`, `DPoP [REDACTED]`} {
		if !strings.Contains(out, kept) {
			t.Fatalf("log lost %s:\n%s", kept, out)
		}
	}
	if !logger.Enabled(t.Context(), slog.LevelDebug) || slog.New(NewLogHandler(&buf, slog.LevelInfo)).Enabled(t.Context(), slog.LevelDebug) {
		t.Fatal("levels not passed through")
	}
	buf.Reset()
	slog.New(NewLogHandler(&buf, slog.LevelInfo)).WithGroup("g").Info("m", slog.String("token", "x"))
	if !strings.Contains(buf.String(), `"g":{"token":"[REDACTED]"}`) {
		t.Fatalf("group: %s", buf.String())
	}
}

func collect(t *testing.T, r *sdkmetric.ManualReader) map[string]metricdata.Aggregation {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := r.Collect(t.Context(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[string]metricdata.Aggregation{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			out[m.Name] = m.Data
		}
	}
	return out
}

func sum(t *testing.T, a metricdata.Aggregation, key, value string) int64 {
	t.Helper()
	s, ok := a.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("%T is not an int64 sum", a)
	}
	var total int64
	for _, dp := range s.DataPoints {
		if v, found := dp.Attributes.Value(attribute.Key(key)); key == "" || found && v.AsString() == value {
			total += dp.Value
		}
	}
	return total
}

func TestObserverRecordsTheSpecSignals(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	defer func() {
		if err := mp.Shutdown(context.WithoutCancel(t.Context())); err != nil {
			t.Error(err)
		}
	}()
	o, err := NewObserver(mp)
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	tun := server.Tunnel{ID: 1, Subject: "alice", Target: netip.MustParseAddrPort("10.0.0.1:22"), Protocol: "HTTP/1.1"}
	o.TunnelOpened(ctx, tun)
	o.TunnelOpened(ctx, tun)
	o.TunnelClosed(ctx, &server.Closed{Tunnel: tun, Reason: server.CloseRevoked, Upstream: 10, Downstream: 20, Duration: 3 * time.Second})
	o.TunnelRejected(ctx, server.Rejection{Status: http.StatusUnauthorized, Reason: "proof"})
	o.TunnelRejected(ctx, server.Rejection{Status: http.StatusForbidden, Reason: "target_mismatch"})

	got := collect(t, reader)
	if n := sum(t, got["relay.tunnels"], "outcome", "opened"); n != 2 {
		t.Errorf("opened %d", n)
	}
	if n := sum(t, got["relay.tunnels"], "outcome", "target_mismatch"); n != 1 {
		t.Errorf("target_mismatch %d", n)
	}
	if n := sum(t, got["relay.tunnels.active"], "", ""); n != 1 {
		t.Errorf("active %d", n)
	}
	if up, down := sum(t, got["relay.tunnel.bytes"], "direction", "upstream"), sum(t, got["relay.tunnel.bytes"], "direction", "downstream"); up != 10 || down != 20 {
		t.Errorf("bytes %d %d", up, down)
	}
	if n := sum(t, got["relay.auth.failures"], "reason", "proof"); n != 1 || sum(t, got["relay.auth.failures"], "", "") != 1 {
		t.Errorf("auth failures %d", n)
	}
	h, ok := got["relay.tunnel.duration"].(metricdata.Histogram[float64])
	if !ok || len(h.DataPoints) != 1 || h.DataPoints[0].Sum != 3 {
		t.Fatalf("duration %+v", got["relay.tunnel.duration"])
	}
	if v, _ := h.DataPoints[0].Attributes.Value("close_reason"); v.AsString() != server.CloseRevoked {
		t.Fatalf("close_reason %v", v)
	}
}

func TestSetupWithoutAnEndpointIsANoOp(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
	mp, shutdown, err := Setup(t.Context(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewObserver(mp); err != nil {
		t.Fatal(err)
	}
	if err := shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestSetupExportsOverOTLP(t *testing.T) {
	var received atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/metrics" && r.Header.Get("Content-Type") == "application/x-protobuf" {
			received.Add(1)
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", srv.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
	mp, shutdown, err := Setup(t.Context(), "test")
	if err != nil {
		t.Fatal(err)
	}
	o, err := NewObserver(mp)
	if err != nil {
		t.Fatal(err)
	}
	o.TunnelRejected(t.Context(), server.Rejection{Status: http.StatusUnauthorized, Reason: "proof"})
	if err := shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if received.Load() == 0 {
		t.Fatal("nothing exported")
	}
}
