// Package telemetry exports the relay's OpenTelemetry metrics and writes its logs through a handler
// that removes anything shaped like a credential.
package telemetry

import (
	"context"
	"errors"
	"os"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"

	"github.com/parallelworks/relay/server"
)

// Setup returns a MeterProvider that exports over OTLP/HTTP when OTEL_EXPORTER_OTLP_ENDPOINT or
// OTEL_EXPORTER_OTLP_METRICS_ENDPOINT is set, configured by the standard OTEL_* variables, and a
// no-op provider otherwise. Call shutdown to flush.
func Setup(ctx context.Context, version string) (mp metric.MeterProvider, shutdown func(context.Context) error, err error) {
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT") == "" {
		return noop.NewMeterProvider(), func(context.Context) error { return nil }, nil
	}
	exp, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return nil, nil, err
	}
	res := resource.NewSchemaless(attribute.String("service.name", "relay"), attribute.String("service.version", version))
	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp, sdkmetric.WithInterval(30*time.Second))),
	)
	return provider, provider.Shutdown, nil
}

// Observer records server events as the metrics SPEC.md names.
type Observer struct {
	tunnels      metric.Int64Counter
	active       metric.Int64UpDownCounter
	bytes        metric.Int64Counter
	duration     metric.Float64Histogram
	authFailures metric.Int64Counter
}

var _ server.Observer = (*Observer)(nil)

// NewObserver creates the instruments on mp.
func NewObserver(mp metric.MeterProvider) (*Observer, error) {
	m := mp.Meter("github.com/parallelworks/relay")
	o := &Observer{}
	var errs [5]error
	o.tunnels, errs[0] = m.Int64Counter("relay.tunnels", metric.WithDescription("Tunnel requests by outcome."), metric.WithUnit("{tunnel}"))
	o.active, errs[1] = m.Int64UpDownCounter("relay.tunnels.active", metric.WithDescription("Open tunnels."), metric.WithUnit("{tunnel}"))
	o.bytes, errs[2] = m.Int64Counter("relay.tunnel.bytes", metric.WithDescription("Bytes relayed by direction."), metric.WithUnit("By"))
	o.duration, errs[3] = m.Float64Histogram("relay.tunnel.duration", metric.WithDescription("Tunnel lifetime by close reason."), metric.WithUnit("s"))
	o.authFailures, errs[4] = m.Int64Counter("relay.auth.failures", metric.WithDescription("Failed authentications by reason."), metric.WithUnit("{request}"))
	if err := errors.Join(errs[:]...); err != nil {
		return nil, err
	}
	return o, nil
}

// TunnelOpened implements server.Observer.
func (o *Observer) TunnelOpened(ctx context.Context, _ server.Tunnel) {
	o.tunnels.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", "opened")))
	o.active.Add(ctx, 1)
}

// TunnelClosed implements server.Observer.
func (o *Observer) TunnelClosed(ctx context.Context, c *server.Closed) {
	o.active.Add(ctx, -1)
	o.bytes.Add(ctx, c.Upstream, metric.WithAttributes(attribute.String("direction", "upstream")))
	o.bytes.Add(ctx, c.Downstream, metric.WithAttributes(attribute.String("direction", "downstream")))
	o.duration.Record(ctx, c.Duration.Seconds(), metric.WithAttributes(attribute.String("close_reason", c.Reason)))
}

// TunnelRejected implements server.Observer.
func (o *Observer) TunnelRejected(ctx context.Context, r server.Rejection) {
	o.tunnels.Add(ctx, 1, metric.WithAttributes(attribute.String("outcome", r.Reason)))
	if r.Status == 401 {
		o.authFailures.Add(ctx, 1, metric.WithAttributes(attribute.String("reason", r.Reason)))
	}
}
