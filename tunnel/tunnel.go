// Package tunnel copies bytes between a client and a target in both directions.
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// BufferSize is the size of each pooled copy buffer.
const BufferSize = 64 << 10

var (
	// ErrIdle reports a tunnel closed because no byte moved for the idle timeout.
	ErrIdle = errors.New("tunnel: idle timeout")
	// ErrPanic reports a tunnel closed because one of its copy goroutines panicked.
	ErrPanic = errors.New("tunnel: panic")
)

var buffers = sync.Pool{New: func() any { return new([BufferSize]byte) }}

// Conn is one side of a tunnel. CloseWrite signals end of stream to the peer while reads continue.
type Conn interface {
	io.ReadWriteCloser
	CloseWrite() error
}

// Counters accumulate the bytes a tunnel moved.
type Counters struct {
	Upstream   atomic.Int64
	Downstream atomic.Int64
}

// Options bound a tunnel.
type Options struct {
	// IdleTimeout closes the tunnel when no byte moves in either direction for this long. Zero disables it.
	IdleTimeout time.Duration
	// OnPanic is called with the recovered value when a copy goroutine panics.
	OnPanic func(recovered any)
}

// Pipe copies client to target and target to client until both directions reach end of stream,
// either side fails, ctx ends, or the tunnel idles out. It closes both connections before returning
// and reports why the tunnel ended: nil for a clean end of stream in both directions.
func Pipe(ctx context.Context, client, target Conn, counters *Counters, opts Options) error {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)

	var activity atomic.Int64
	activity.Store(time.Now().UnixNano())

	var wg sync.WaitGroup
	run := func(dst, src Conn, n *atomic.Int64) {
		defer wg.Done()
		defer func() {
			if r := recover(); r != nil {
				if opts.OnPanic != nil {
					opts.OnPanic(r)
				}
				cancel(fmt.Errorf("%w: %v", ErrPanic, r))
			}
		}()
		err := copyHalf(dst, src, n, &activity)
		if err != nil {
			cancel(err)
		}
	}
	wg.Add(2)
	go run(target, client, &counters.Upstream)
	go run(client, target, &counters.Downstream)

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	var idle <-chan time.Time
	var ticker *time.Ticker
	if opts.IdleTimeout > 0 {
		ticker = time.NewTicker(opts.IdleTimeout / 4)
		defer ticker.Stop()
		idle = ticker.C
	}
	for {
		select {
		case <-done:
			return closeBoth(ctx, client, target)
		case <-ctx.Done():
			err := closeBoth(ctx, client, target)
			<-done
			return err
		case <-idle:
			if time.Since(time.Unix(0, activity.Load())) >= opts.IdleTimeout {
				cancel(ErrIdle)
			}
		}
	}
}

func closeBoth(ctx context.Context, a, b Conn) error {
	closeErr := errors.Join(a.Close(), b.Close())
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	return closeErr
}

func copyHalf(dst, src Conn, n, activity *atomic.Int64) error {
	buf := buffers.Get().(*[BufferSize]byte)
	defer buffers.Put(buf)
	for {
		nr, rerr := src.Read(buf[:])
		if nr > 0 {
			activity.Store(time.Now().UnixNano())
			nw, werr := dst.Write(buf[:nr])
			n.Add(int64(nw))
			if werr != nil {
				return werr
			}
			if nw != nr {
				return io.ErrShortWrite
			}
		}
		if errors.Is(rerr, io.EOF) {
			return dst.CloseWrite()
		}
		if rerr != nil {
			return rerr
		}
	}
}
