package server

import (
	"context"
	"log/slog"
	"math"
	"net"
	"net/netip"
	"sync"
	"time"
)

// sourceOf groups clients by IPv4 address or IPv6 /64, the smallest block a host commonly holds.
func sourceOf(remoteAddr string) netip.Prefix {
	ap, err := netip.ParseAddrPort(remoteAddr)
	if err != nil {
		return netip.Prefix{}
	}
	return sourceOfAddr(ap.Addr())
}

func sourceOfAddr(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	if a.Is4() {
		return netip.PrefixFrom(a, 32)
	}
	return netip.PrefixFrom(a, 64).Masked()
}

type sourceLimitedListener struct {
	net.Listener
	max    int
	logger *slog.Logger
	mu     sync.Mutex
	counts map[netip.Prefix]int
}

func newSourceLimitedListener(ln net.Listener, maxPerSource int, logger *slog.Logger) *sourceLimitedListener {
	return &sourceLimitedListener{Listener: ln, max: maxPerSource, logger: logger, counts: map[netip.Prefix]int{}}
}

// Accept closes connections from a source that already holds its share, before any TLS work.
func (l *sourceLimitedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if tc, ok := c.(*net.TCPConn); ok {
			if err := tc.SetNoDelay(true); err != nil {
				l.logger.LogAttrs(context.Background(), slog.LevelWarn, "connection.nodelay_failed", slog.String("error", err.Error()))
			}
		}
		src := sourceOf(c.RemoteAddr().String())
		if l.acquire(src) {
			return &sourceConn{Conn: c, release: sync.OnceFunc(func() { l.release(src) })}, nil
		}
		attrs := []slog.Attr{slog.String("source", src.String())}
		if err := c.Close(); err != nil {
			attrs = append(attrs, slog.String("error", err.Error()))
		}
		l.logger.LogAttrs(context.Background(), slog.LevelInfo, "connection.refused", attrs...)
	}
}

func (l *sourceLimitedListener) acquire(src netip.Prefix) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.counts[src] >= l.max {
		return false
	}
	l.counts[src]++
	return true
}

func (l *sourceLimitedListener) release(src netip.Prefix) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.counts[src]--
	if l.counts[src] == 0 {
		delete(l.counts, src)
	}
}

type sourceConn struct {
	net.Conn
	release func()
}

func (c *sourceConn) Close() error {
	defer c.release()
	return c.Conn.Close()
}

// failureLimiter is a token bucket per source: each failed authentication takes a token, and a
// source with none left is refused until the bucket refills at perMinute tokens a minute.
type failureLimiter struct {
	burst   float64
	rate    float64
	maxSize int
	mu      sync.Mutex
	buckets map[netip.Prefix]*bucket
}

type bucket struct {
	tokens float64
	at     time.Time
}

func newFailureLimiter(perMinute, maxSources int) *failureLimiter {
	return &failureLimiter{
		burst:   float64(perMinute),
		rate:    float64(perMinute) / time.Minute.Seconds(),
		maxSize: maxSources,
		buckets: map[netip.Prefix]*bucket{},
	}
}

func (f *failureLimiter) refill(b *bucket, now time.Time) {
	b.tokens = math.Min(f.burst, b.tokens+now.Sub(b.at).Seconds()*f.rate)
	b.at = now
}

// allow reports whether src may try to authenticate and, when it may not, how long until it can.
func (f *failureLimiter) allow(src netip.Prefix, now time.Time) (wait time.Duration, ok bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, found := f.buckets[src]
	if !found {
		return 0, true
	}
	f.refill(b, now)
	if b.tokens >= 1 {
		return 0, true
	}
	return time.Duration(math.Ceil((1 - b.tokens) / f.rate * float64(time.Second))), false
}

func (f *failureLimiter) fail(src netip.Prefix, now time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, found := f.buckets[src]
	if !found {
		if len(f.buckets) >= f.maxSize {
			f.prune(now)
		}
		if len(f.buckets) >= f.maxSize {
			return
		}
		b = &bucket{tokens: f.burst, at: now}
		f.buckets[src] = b
	}
	f.refill(b, now)
	b.tokens = math.Max(0, b.tokens-1)
}

func (f *failureLimiter) prune(now time.Time) {
	for src, b := range f.buckets {
		f.refill(b, now)
		if b.tokens >= f.burst {
			delete(f.buckets, src)
		}
	}
}
