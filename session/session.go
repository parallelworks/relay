// Package session keeps every open tunnel's authorization current by re-introspecting its
// relay_session and closing the tunnel when the authorization server withdraws it.
package session

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/parallelworks/relay/introspect"
)

const (
	// DefaultInterval is the default time between re-introspections.
	DefaultInterval = 60 * time.Second
	// DefaultGrace is how long a session may go without a valid answer before it is closed.
	DefaultGrace = 120 * time.Second
	checkTimeout = 10 * time.Second
)

// Reasons a session is closed. Each is the cause of the session's context.
var (
	ErrRevoked         = errors.New("session: authorization server reports the session inactive")
	ErrSubjectMismatch = errors.New("session: subject changed")
	ErrExpired         = errors.New("session: expired")
	ErrNoAnswer        = errors.New("session: no valid answer from the authorization server within the grace period")
)

// Introspector answers whether a relay_session is still active.
type Introspector interface {
	Session(ctx context.Context, token string) (introspect.Session, error)
}

// Options configure a Registry. Zero values use the defaults.
type Options struct {
	Interval time.Duration
	Grace    time.Duration
}

// Registry tracks open sessions.
type Registry struct {
	intro    Introspector
	interval time.Duration
	grace    time.Duration
	nextID   atomic.Uint64
	mu       sync.Mutex
	open     map[uint64]*Session
}

// NewRegistry returns a registry that checks sessions with intro.
func NewRegistry(intro Introspector, opts Options) *Registry {
	if opts.Interval <= 0 {
		opts.Interval = DefaultInterval
	}
	if opts.Grace <= 0 {
		opts.Grace = DefaultGrace
	}
	return &Registry{intro: intro, interval: opts.Interval, grace: opts.Grace, open: map[uint64]*Session{}}
}

// Session is one open tunnel's authorization.
type Session struct {
	ID      uint64
	Subject string
	Target  netip.AddrPort
	Started time.Time
	token   string
}

// Start begins watching token for subject and returns a context that ends, with one of the
// package's errors as its cause, when the session must close. Call stop when the tunnel ends.
func (r *Registry) Start(parent context.Context, subject, token string, target netip.AddrPort) (ctx context.Context, s *Session, stop func()) {
	s = &Session{ID: r.nextID.Add(1), Subject: subject, Target: target, Started: time.Now(), token: token}
	ctx, cancel := context.WithCancelCause(parent)
	r.mu.Lock()
	r.open[s.ID] = s
	r.mu.Unlock()
	done := make(chan struct{})
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		r.watch(ctx, s, cancel, done)
	}()
	var once sync.Once
	stop = func() {
		once.Do(func() {
			close(done)
			<-watched
			cancel(nil)
			r.mu.Lock()
			delete(r.open, s.ID)
			r.mu.Unlock()
		})
	}
	return ctx, s, stop
}

// Open returns the number of open sessions.
func (r *Registry) Open() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.open)
}

func (r *Registry) watch(ctx context.Context, s *Session, cancel context.CancelCauseFunc, done <-chan struct{}) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	lastValid := time.Now()
	for {
		select {
		case <-done:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		valid, cause := r.check(ctx, s)
		if valid {
			lastValid = time.Now()
		}
		if cause == nil && time.Since(lastValid) >= r.grace {
			cause = ErrNoAnswer
		}
		if cause != nil {
			cancel(cause)
			return
		}
	}
}

func (r *Registry) check(ctx context.Context, s *Session) (valid bool, cause error) {
	ctx, cancel := context.WithTimeout(ctx, checkTimeout)
	defer cancel()
	ans, err := r.intro.Session(ctx, s.token)
	if err != nil {
		return false, nil
	}
	if !ans.Active {
		return true, ErrRevoked
	}
	if ans.Subject != s.Subject {
		return true, ErrSubjectMismatch
	}
	if !ans.Expires.IsZero() && !ans.Expires.After(time.Now()) {
		return true, ErrExpired
	}
	return true, nil
}
