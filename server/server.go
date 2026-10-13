// Package server accepts CONNECT tunnel requests, authorizes each one by DPoP proof and token
// introspection, and relays bytes to the target the authorization server names.
package server

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/parallelworks/relay/dpop"
	"github.com/parallelworks/relay/introspect"
	"github.com/parallelworks/relay/policy"
	"github.com/parallelworks/relay/session"
)

// MaxHeaderBytes caps a request's header section.
const MaxHeaderBytes = 8 << 10

// ErrClosed is the cause of every tunnel the server cuts off when it closes.
var ErrClosed = errors.New("server: closed")

// Introspector checks tunnel access tokens.
type Introspector interface {
	AccessToken(ctx context.Context, token string) (introspect.Token, error)
}

// Tunnel describes an open tunnel.
type Tunnel struct {
	ID       uint64
	Subject  string
	Target   netip.AddrPort
	Protocol string
}

// Closed describes how a tunnel ended.
type Closed struct {
	Tunnel
	Reason     string
	Upstream   int64
	Downstream int64
	Duration   time.Duration
}

// Rejection describes a tunnel request the relay refused.
type Rejection struct {
	Status int
	Reason string
}

// Observer receives tunnel events. Implementations must be safe for concurrent use.
type Observer interface {
	TunnelOpened(ctx context.Context, t Tunnel)
	TunnelClosed(ctx context.Context, c *Closed)
	TunnelRejected(ctx context.Context, r Rejection)
}

// Limits bound the server's resource use. Zero values use the defaults.
type Limits struct {
	MaxTunnels           int
	MaxTunnelsPerSource  int
	MaxConnsPerSource    int
	FailedAuthPerMinute  int
	MaxTrackedSources    int
	DialTimeout          time.Duration
	IntrospectionTimeout time.Duration
	ReadHeaderTimeout    time.Duration
	IdleTimeout          time.Duration
}

func (l Limits) withDefaults() Limits {
	positive(&l.MaxTunnels, 10_000)
	positive(&l.MaxTunnelsPerSource, 256)
	positive(&l.MaxConnsPerSource, 64)
	positive(&l.FailedAuthPerMinute, 30)
	positive(&l.MaxTrackedSources, 100_000)
	positive(&l.DialTimeout, 5*time.Second)
	positive(&l.IntrospectionTimeout, 10*time.Second)
	positive(&l.ReadHeaderTimeout, 10*time.Second)
	positive(&l.IdleTimeout, time.Hour)
	return l
}

func positive[T int | time.Duration](v *T, def T) {
	if *v <= 0 {
		*v = def
	}
}

// Config wires a Server's dependencies.
type Config struct {
	Verifier       *dpop.Verifier
	Nonces         *dpop.Nonces
	Introspector   Introspector
	Policy         *policy.Policy
	Sessions       *session.Registry
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	Logger         *slog.Logger
	Observer       Observer
	Limits         Limits
}

// Server is a relay server.
type Server struct {
	cfg      Config
	limits   Limits
	http     *http.Server
	failures *failureLimiter
	dialer   *net.Dialer

	mu       sync.Mutex
	closing  bool
	inflight int
	sources  map[netip.Prefix]int
	nextID   uint64
	cancels  map[uint64]context.CancelCauseFunc
	active   sync.WaitGroup
}

type nopObserver struct{}

func (nopObserver) TunnelOpened(context.Context, Tunnel)      {}
func (nopObserver) TunnelClosed(context.Context, *Closed)     {}
func (nopObserver) TunnelRejected(context.Context, Rejection) {}

// New returns a server for cfg.
func New(cfg *Config) (*Server, error) {
	if cfg.Verifier == nil || cfg.Introspector == nil || cfg.Policy == nil || cfg.Sessions == nil || cfg.GetCertificate == nil {
		return nil, errors.New("server: Verifier, Introspector, Policy, Sessions and GetCertificate are required")
	}
	cfg = new(*cfg)
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.Observer == nil {
		cfg.Observer = nopObserver{}
	}
	limits := cfg.Limits.withDefaults()
	s := &Server{
		cfg:      *cfg,
		limits:   limits,
		failures: newFailureLimiter(limits.FailedAuthPerMinute, limits.MaxTrackedSources),
		dialer:   cfg.Policy.Dialer(limits.DialTimeout),
		sources:  map[netip.Prefix]int{},
		cancels:  map[uint64]context.CancelCauseFunc{},
	}
	s.dialer.KeepAliveConfig = net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second, Interval: 15 * time.Second, Count: 4}
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	s.http = &http.Server{
		Handler:           s,
		ReadHeaderTimeout: limits.ReadHeaderTimeout,
		MaxHeaderBytes:    MaxHeaderBytes,
		Protocols:         protocols,
		ErrorLog:          slog.NewLogLogger(cfg.Logger.Handler(), slog.LevelDebug),
		TLSConfig: &tls.Config{
			MinVersion:     tls.VersionTLS13,
			GetCertificate: cfg.GetCertificate,
			NextProtos:     []string{"h2", "http/1.1"},
		},
		HTTP2: &http.HTTP2Config{
			MaxConcurrentStreams:          100,
			MaxReceiveBufferPerStream:     4 << 20,
			MaxReceiveBufferPerConnection: 16 << 20,
			SendPingTimeout:               30 * time.Second,
		},
	}
	return s, nil
}

// Serve accepts connections on ln, a plain TCP listener; the server adds TLS. It returns
// http.ErrServerClosed after Shutdown or Close.
func (s *Server) Serve(ln net.Listener) error {
	return s.http.ServeTLS(newSourceLimitedListener(ln, s.limits.MaxConnsPerSource, s.cfg.Logger), "", "")
}

// Shutdown stops accepting tunnels and waits for open ones to end. When ctx ends first it closes
// the remaining tunnels with ErrClosed and returns ctx's error.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	s.closing = true
	s.mu.Unlock()
	err := s.http.Shutdown(ctx)
	done := make(chan struct{})
	go func() {
		s.active.Wait()
		close(done)
	}()
	select {
	case <-done:
		return err
	case <-ctx.Done():
		s.cancelAll()
		<-done
		if err == nil {
			err = ctx.Err()
		}
		return errors.Join(err, s.http.Close())
	}
}

// Close closes every tunnel and connection immediately.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closing = true
	s.mu.Unlock()
	s.cancelAll()
	err := s.http.Close()
	s.active.Wait()
	return err
}

// Tunnels returns the number of requests being authorized or relayed.
func (s *Server) Tunnels() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inflight
}

func (s *Server) cancelAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, cancel := range s.cancels {
		cancel(ErrClosed)
	}
}

// enter admits a request from src and returns a context the server cancels with ErrClosed when it
// closes, and the function that ends the request.
func (s *Server) enter(ctx context.Context, src netip.Prefix) (context.Context, func(), *rejection) {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch {
	case s.closing:
		return ctx, nil, &rejection{status: http.StatusServiceUnavailable, reason: reasonClosing, retryAfter: retryAfterBusy}
	case s.inflight >= s.limits.MaxTunnels:
		return ctx, nil, &rejection{status: http.StatusServiceUnavailable, reason: reasonCapacity, retryAfter: retryAfterBusy}
	case s.sources[src] >= s.limits.MaxTunnelsPerSource:
		return ctx, nil, &rejection{status: http.StatusTooManyRequests, reason: reasonSourceLimit, retryAfter: retryAfterBusy}
	}
	s.inflight++
	s.sources[src]++
	s.active.Add(1)
	s.nextID++
	id := s.nextID
	ctx, cancel := context.WithCancelCause(ctx)
	s.cancels[id] = cancel
	return ctx, func() {
		cancel(nil)
		s.mu.Lock()
		delete(s.cancels, id)
		s.inflight--
		s.sources[src]--
		if s.sources[src] == 0 {
			delete(s.sources, src)
		}
		s.mu.Unlock()
		s.active.Done()
	}, nil
}

// TokenID identifies a token in logs without revealing it: the first 8 hex digits of its SHA-256.
func TokenID(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:4])
}
