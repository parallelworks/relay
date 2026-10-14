//go:debug fips140=only

// Command relay runs a relay server.
package main

import (
	"bytes"
	"context"
	"crypto/fips140"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/parallelworks/relay/dpop"
	"github.com/parallelworks/relay/introspect"
	"github.com/parallelworks/relay/policy"
	"github.com/parallelworks/relay/registration"
	"github.com/parallelworks/relay/server"
	"github.com/parallelworks/relay/session"
	"github.com/parallelworks/relay/telemetry"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:], os.Stdout, os.Stderr, nil)
	stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "relay:", err)
		os.Exit(1)
	}
}

func version() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" {
		return info.Main.Version
	}
	return "(devel)"
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, ready func(net.Addr)) error {
	flags := flag.NewFlagSet("relay", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "/etc/relay/config.json", "configuration file")
	showVersion := flags.Bool("version", false, "print the version and FIPS 140-3 status, then exit")
	registerOnly := flags.Bool("register", false, "register with the authorization server if needed, print the client_id, then exit")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		_, err := fmt.Fprintf(stdout, "relay %s\nfips140 module %s, enabled %t, enforced %t\n",
			version(), fips140.Version(), fips140.Enabled(), fips140.Enforced())
		return err
	}
	data, err := readFile(*configPath)
	if err != nil {
		return err
	}
	if len(data) > MaxConfigSize {
		return fmt.Errorf("config: larger than %d bytes", MaxConfigSize)
	}
	cfg, err := decodeConfig(data)
	if err != nil {
		return err
	}
	if *registerOnly {
		return register(ctx, cfg, stdout)
	}
	logger := slog.New(telemetry.NewLogHandler(stderr, cfg.LogLevel))
	mp, shutdown, err := telemetry.Setup(ctx, version())
	if err != nil {
		return err
	}
	observer, err := telemetry.NewObserver(mp)
	if err != nil {
		return errors.Join(err, shutdown(context.WithoutCancel(ctx)))
	}
	err = serve(ctx, cfg, logger, observer, ready)
	flushCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return errors.Join(err, shutdown(flushCtx))
}

// connect discovers the authorization server and loads or registers the relay's credentials.
func connect(ctx context.Context, cfg *Config) (*http.Client, introspect.Metadata, introspect.Credentials, error) {
	roots, err := issuerRoots(cfg.IssuerCAFile)
	if err != nil {
		return nil, introspect.Metadata{}, introspect.Credentials{}, err
	}
	hc := introspect.NewHTTPClient(roots)
	meta, err := introspect.Discover(ctx, hc, cfg.Issuer)
	if err != nil {
		hc.CloseIdleConnections()
		return nil, introspect.Metadata{}, introspect.Credentials{}, err
	}
	creds, err := credentials(ctx, cfg, hc, &meta)
	if err != nil {
		hc.CloseIdleConnections()
		return nil, introspect.Metadata{}, introspect.Credentials{}, err
	}
	return hc, meta, creds, nil
}

func register(ctx context.Context, cfg *Config, stdout io.Writer) error {
	hc, _, creds, err := connect(ctx, cfg)
	if err != nil {
		return err
	}
	hc.CloseIdleConnections()
	_, err = fmt.Fprintf(stdout, "client_id %s\n", creds.ClientID)
	return err
}

func serve(ctx context.Context, cfg *Config, logger *slog.Logger, observer server.Observer, ready func(net.Addr)) (err error) {
	hc, meta, creds, err := connect(ctx, cfg)
	if err != nil {
		return err
	}
	defer hc.CloseIdleConnections()
	ic, err := introspect.NewClient(meta, creds, hc)
	if err != nil {
		return err
	}
	pol, err := policy.New(cfg.Egress.Allow, cfg.Egress.Exceptions)
	if err != nil {
		return err
	}
	nonces, err := newNonces(cfg.DPoPNonces)
	if err != nil {
		return err
	}
	certs, err := server.LoadCertificates(cfg.TLS.Dir, cfg.TLS.Cert, cfg.TLS.Key)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, certs.Close()) }()

	l := cfg.Limits
	srv, err := server.New(&server.Config{
		Verifier:       dpop.NewVerifier(dpop.Options{Nonces: nonces}),
		Nonces:         nonces,
		Introspector:   ic,
		Policy:         pol,
		Sessions:       session.NewRegistry(ic, session.Options{Interval: time.Duration(cfg.Session.Interval), Grace: time.Duration(cfg.Session.Grace)}),
		GetCertificate: certs.GetCertificate,
		Logger:         logger,
		Observer:       observer,
		Limits: server.Limits{
			MaxTunnels:           l.MaxTunnels,
			MaxTunnelsPerSource:  l.MaxTunnelsPerSource,
			MaxConnsPerSource:    l.MaxConnsPerSource,
			FailedAuthPerMinute:  l.FailedAuthPerMinute,
			DialTimeout:          time.Duration(l.DialTimeout),
			IntrospectionTimeout: time.Duration(l.IntrospectionTimeout),
			ReadHeaderTimeout:    time.Duration(l.ReadHeaderTimeout),
			IdleTimeout:          time.Duration(l.IdleTimeout),
			MaxTunnelLifetime:    time.Duration(l.MaxTunnelLifetime),
		},
	})
	if err != nil {
		return err
	}
	lc := net.ListenConfig{KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second, Interval: 15 * time.Second, Count: 4}}
	ln, err := lc.Listen(ctx, "tcp", cfg.Listen)
	if err != nil {
		return err
	}
	logger.LogAttrs(ctx, slog.LevelInfo, "relay.started",
		slog.String("version", version()),
		slog.String("listen", ln.Addr().String()),
		slog.String("client_id", ic.ClientID()),
		slog.String("fips140_module", fips140.Version()),
		slog.Bool("fips140_enforced", fips140.Enforced()))
	if ready != nil {
		ready(ln.Addr())
	}

	watchCtx, stopWatch := context.WithCancel(ctx)
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		certs.Watch(watchCtx, time.Duration(cfg.TLS.ReloadInterval), logger)
	}()
	defer func() {
		stopWatch()
		<-watched
	}()

	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	select {
	case serr := <-served:
		return serr
	case <-ctx.Done():
	}
	logger.LogAttrs(context.WithoutCancel(ctx), slog.LevelInfo, "relay.stopping", slog.Int("tunnels", srv.Tunnels()))
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Duration(cfg.ShutdownTimeout))
	defer cancel()
	err = srv.Shutdown(shutdownCtx)
	if serr := <-served; !errors.Is(serr, http.ErrServerClosed) {
		err = errors.Join(err, serr)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		logger.LogAttrs(shutdownCtx, slog.LevelWarn, "relay.shutdown_timeout")
		return nil
	}
	return err
}

func issuerRoots(path string) (*x509.CertPool, error) {
	if path == "" {
		return nil, nil
	}
	pem, err := readFile(path)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return nil, errors.New("issuer_ca_file: no certificates")
	}
	return roots, nil
}

func credentials(ctx context.Context, cfg *Config, hc *http.Client, meta *introspect.Metadata) (creds introspect.Credentials, err error) {
	store, err := registration.Open(cfg.Registration.Dir, registration.Options{})
	if err != nil {
		return introspect.Credentials{}, err
	}
	defer func() { err = errors.Join(err, store.Close()) }()
	creds, err = store.Load(cfg.Issuer)
	if !errors.Is(err, registration.ErrNotRegistered) {
		return creds, err
	}
	if cfg.Registration.InitialAccessTokenFile == "" {
		return introspect.Credentials{}, errors.New("relay is not registered and registration.initial_access_token_file is not set")
	}
	token, err := readFile(cfg.Registration.InitialAccessTokenFile)
	if err != nil {
		return introspect.Credentials{}, err
	}
	return store.Register(ctx, hc, &registration.Request{
		Endpoint:           meta.RegistrationEndpoint,
		Issuer:             cfg.Issuer,
		InitialAccessToken: string(bytes.TrimSpace(token)),
		ClientName:         cfg.Registration.ClientName,
		SoftwareVersion:    version(),
	})
}

func newNonces(cfg *DPoPNonces) (*dpop.Nonces, error) {
	switch {
	case cfg == nil:
		return nil, nil
	case cfg.KeyFile == "":
		return dpop.NewRandomNonces(time.Duration(cfg.Lifetime))
	}
	key, err := readFile(cfg.KeyFile)
	if err != nil {
		return nil, err
	}
	return dpop.NewNonces(key, time.Duration(cfg.Lifetime))
}
