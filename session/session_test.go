package session

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/goleak"

	"github.com/parallelworks/relay/introspect"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

type fakeIntrospector struct {
	mu    sync.Mutex
	ans   introspect.Session
	err   error
	calls int
}

func (f *fakeIntrospector) Session(ctx context.Context, token string) (introspect.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if token != "tok" {
		return introspect.Session{}, errors.New("wrong token")
	}
	if err := ctx.Err(); err != nil {
		return introspect.Session{}, err
	}
	return f.ans, f.err
}

func (f *fakeIntrospector) set(ans introspect.Session, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ans, f.err = ans, err
}

var target = netip.MustParseAddrPort("10.0.0.1:22")

func start(t *testing.T, f *fakeIntrospector, opts Options) (*Registry, context.Context, func()) {
	t.Helper()
	r := NewRegistry(f, opts)
	ctx, s, stop := r.Start(t.Context(), "alice", "tok", target)
	if s.Subject != "alice" || s.Target != target || s.ID == 0 {
		t.Fatalf("session %+v", s)
	}
	return r, ctx, stop
}

func expectOpenFor(ctx context.Context, t *testing.T, d time.Duration) {
	t.Helper()
	time.Sleep(d)
	synctest.Wait()
	if err := ctx.Err(); err != nil {
		t.Fatalf("session closed after %v: %v", d, context.Cause(ctx))
	}
}

func expectClosed(ctx context.Context, t *testing.T, want error) {
	t.Helper()
	synctest.Wait()
	if !errors.Is(context.Cause(ctx), want) {
		t.Fatalf("cause = %v, want %v", context.Cause(ctx), want)
	}
}

func TestClosesWhenSessionInactive(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		f := &fakeIntrospector{ans: introspect.Session{Active: true, Subject: "alice"}}
		_, ctx, stop := start(t, f, Options{Interval: time.Minute})
		defer stop()
		expectOpenFor(ctx, t, 3*time.Minute)
		f.set(introspect.Session{Active: false, Subject: "alice"}, nil)
		time.Sleep(time.Minute)
		expectClosed(ctx, t, ErrRevoked)
	})
}

func TestClosesOnSubjectMismatch(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		f := &fakeIntrospector{ans: introspect.Session{Active: true, Subject: "mallory"}}
		_, ctx, stop := start(t, f, Options{Interval: time.Minute})
		defer stop()
		time.Sleep(time.Minute)
		expectClosed(ctx, t, ErrSubjectMismatch)
	})
}

func TestClosesWhenSessionExpires(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		f := &fakeIntrospector{ans: introspect.Session{Active: true, Subject: "alice", Expires: time.Now().Add(2 * time.Minute)}}
		_, ctx, stop := start(t, f, Options{Interval: time.Minute})
		defer stop()
		expectOpenFor(ctx, t, time.Minute)
		time.Sleep(time.Minute)
		expectClosed(ctx, t, ErrExpired)
	})
}

func TestFailsClosedAfterGrace(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		f := &fakeIntrospector{err: introspect.ErrUnavailable}
		_, ctx, stop := start(t, f, Options{Interval: time.Minute, Grace: 2 * time.Minute})
		defer stop()
		expectOpenFor(ctx, t, time.Minute)
		time.Sleep(time.Minute)
		expectClosed(ctx, t, ErrNoAnswer)
	})
}

func TestValidAnswerResetsGrace(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		f := &fakeIntrospector{err: introspect.ErrUnavailable}
		_, ctx, stop := start(t, f, Options{Interval: time.Minute, Grace: 2 * time.Minute})
		defer stop()
		expectOpenFor(ctx, t, time.Minute)
		f.set(introspect.Session{Active: true, Subject: "alice"}, nil)
		expectOpenFor(ctx, t, time.Minute)
		f.set(introspect.Session{}, introspect.ErrUnavailable)
		expectOpenFor(ctx, t, time.Minute)
		time.Sleep(time.Minute)
		expectClosed(ctx, t, ErrNoAnswer)
	})
}

func TestStopRemovesSessionAndIsIdempotent(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		f := &fakeIntrospector{ans: introspect.Session{Active: true, Subject: "alice"}}
		r, ctx, stop := start(t, f, Options{})
		_, _, stop2 := r.Start(t.Context(), "bob", "tok", target)
		if r.Open() != 2 {
			t.Fatalf("Open = %d", r.Open())
		}
		stop()
		stop()
		if r.Open() != 1 {
			t.Fatalf("Open after stop = %d", r.Open())
		}
		if cause := context.Cause(ctx); !errors.Is(cause, context.Canceled) || errors.Is(cause, ErrRevoked) {
			t.Fatalf("stopped session cause = %v", context.Cause(ctx))
		}
		stop2()
		time.Sleep(10 * DefaultInterval)
		f.mu.Lock()
		calls := f.calls
		f.mu.Unlock()
		if calls != 0 {
			t.Fatalf("stopped sessions were checked %d times", calls)
		}
	})
}

func TestParentCancellationStopsWatching(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		f := &fakeIntrospector{ans: introspect.Session{Active: true, Subject: "alice"}}
		r := NewRegistry(f, Options{})
		parent, cancel := context.WithCancel(t.Context())
		ctx, _, stop := r.Start(parent, "alice", "tok", target)
		defer stop()
		cancel()
		synctest.Wait()
		if ctx.Err() == nil {
			t.Fatal("session outlived its parent")
		}
	})
}

func TestDefaults(t *testing.T) {
	t.Parallel()
	r := NewRegistry(&fakeIntrospector{}, Options{Interval: -1, Grace: -1})
	if r.interval != DefaultInterval || r.grace != DefaultGrace {
		t.Fatalf("interval %v grace %v", r.interval, r.grace)
	}
}
