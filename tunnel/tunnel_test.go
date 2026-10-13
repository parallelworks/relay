package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

type memConn struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (c memConn) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c memConn) Write(b []byte) (int, error) { return c.w.Write(b) }
func (c memConn) CloseWrite() error           { return c.w.Close() }
func (c memConn) Close() error                { return errors.Join(c.r.Close(), c.w.Close()) }

func memPair() (a, b memConn) {
	ar, bw := io.Pipe()
	br, aw := io.Pipe()
	return memConn{r: ar, w: aw}, memConn{r: br, w: bw}
}

func tcpPair(t *testing.T) (client, server *net.TCPConn) {
	t.Helper()
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cerr := ln.Close(); cerr != nil {
			t.Error(cerr)
		}
	}()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	dialed, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn := <-accepted
	if conn == nil {
		t.Fatal("accept failed")
	}
	return dialed.(*net.TCPConn), conn.(*net.TCPConn)
}

func readExactly(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatal(err)
	}
	return buf
}

func TestPipeCopiesBothWaysWithHalfClose(t *testing.T) {
	t.Parallel()
	clientApp, clientRelay := tcpPair(t)
	targetRelay, targetApp := tcpPair(t)
	defer func() {
		if err := errors.Join(clientApp.Close(), targetApp.Close()); err != nil {
			t.Log(err)
		}
	}()
	var counters Counters
	result := make(chan error, 1)
	go func() { result <- Pipe(t.Context(), clientRelay, targetRelay, &counters, Options{}) }()

	up := bytes.Repeat([]byte("u"), 3*BufferSize+17)
	if _, err := clientApp.Write(up); err != nil {
		t.Fatal(err)
	}
	if got := readExactly(t, targetApp, len(up)); !bytes.Equal(got, up) {
		t.Fatal("upstream bytes differ")
	}
	if err := clientApp.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if n, err := targetApp.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("target did not see the client's half-close: %d %v", n, err)
	}
	down := []byte(strings.Repeat("d", 1000))
	if _, err := targetApp.Write(down); err != nil {
		t.Fatalf("target cannot write after the client half-closed: %v", err)
	}
	if got := readExactly(t, clientApp, len(down)); !bytes.Equal(got, down) {
		t.Fatal("downstream bytes differ")
	}
	if err := targetApp.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatalf("clean end of stream reported %v", err)
	}
	if counters.Upstream.Load() != int64(len(up)) || counters.Downstream.Load() != int64(len(down)) {
		t.Fatalf("counters up=%d down=%d", counters.Upstream.Load(), counters.Downstream.Load())
	}
}

func TestPipeEndsWhenContextEnds(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		clientApp, clientRelay := memPair()
		targetRelay, targetApp := memPair()
		ctx, cancel := context.WithCancelCause(t.Context())
		result := make(chan error, 1)
		go func() { result <- Pipe(ctx, clientRelay, targetRelay, new(Counters), Options{}) }()
		synctest.Wait()
		revoked := errors.New("revoked")
		cancel(revoked)
		if err := <-result; !errors.Is(err, revoked) {
			t.Fatalf("Pipe = %v, want the cancellation cause", err)
		}
		if _, err := clientApp.Read(make([]byte, 1)); err == nil {
			t.Fatal("client side still open")
		}
		if _, err := targetApp.Read(make([]byte, 1)); err == nil {
			t.Fatal("target side still open")
		}
	})
}

func TestPipeIdleTimeout(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		clientApp, clientRelay := memPair()
		targetRelay, targetApp := memPair()
		defer func() {
			if err := errors.Join(clientApp.Close(), targetApp.Close()); err != nil {
				t.Log(err)
			}
		}()
		result := make(chan error, 1)
		start := time.Now()
		go func() {
			result <- Pipe(t.Context(), clientRelay, targetRelay, new(Counters), Options{IdleTimeout: time.Minute})
		}()
		go func() {
			if _, err := io.Copy(io.Discard, targetApp); err != nil {
				return
			}
		}()
		time.Sleep(50 * time.Second)
		if _, err := clientApp.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, ErrIdle) {
			t.Fatalf("Pipe = %v, want ErrIdle", err)
		}
		if elapsed := time.Since(start); elapsed < 110*time.Second || elapsed > 125*time.Second {
			t.Fatalf("idle timeout fired after %v; activity at 50s should push it to about 110s", elapsed)
		}
	})
}

type panicConn struct{ memConn }

func (panicConn) Read([]byte) (int, error) { panic("boom") }

func TestPanicClosesOnlyThatTunnel(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		_, clientRelay := memPair()
		targetRelay, _ := memPair()
		var recovered atomic.Value
		err := Pipe(t.Context(), panicConn{clientRelay}, targetRelay, new(Counters), Options{
			OnPanic: func(r any) { recovered.Store(r) },
		})
		if !errors.Is(err, ErrPanic) {
			t.Fatalf("Pipe = %v, want ErrPanic", err)
		}
		if recovered.Load() != "boom" {
			t.Fatalf("OnPanic got %v", recovered.Load())
		}

		healthyApp, healthyRelay := memPair()
		healthyTarget, healthyTargetApp := memPair()
		result := make(chan error, 1)
		go func() { result <- Pipe(t.Context(), healthyRelay, healthyTarget, new(Counters), Options{}) }()
		go func() {
			if _, werr := healthyApp.Write([]byte("ok")); werr != nil {
				return
			}
			if cerr := healthyApp.CloseWrite(); cerr != nil {
				return
			}
		}()
		if got := readExactly(t, healthyTargetApp, 2); string(got) != "ok" {
			t.Fatalf("other tunnel got %q", got)
		}
		if err := healthyTargetApp.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadAll(healthyApp); err != nil {
			t.Fatal(err)
		}
		if err := <-result; err != nil {
			t.Fatalf("other tunnel ended with %v", err)
		}
	})
	t.Run("without a hook", func(t *testing.T) {
		synctest.Test(t, func(t *testing.T) {
			_, clientRelay := memPair()
			targetRelay, _ := memPair()
			if err := Pipe(t.Context(), panicConn{clientRelay}, targetRelay, new(Counters), Options{}); !errors.Is(err, ErrPanic) {
				t.Fatalf("Pipe = %v", err)
			}
		})
	})
}

type failingConn struct {
	memConn
	writeErr      error
	short         bool
	closeWriteErr error
	closeErr      error
}

func (c failingConn) Write(b []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	if c.short {
		return len(b) - 1, nil
	}
	return c.memConn.Write(b)
}

func (c failingConn) CloseWrite() error {
	if c.closeWriteErr != nil {
		return c.closeWriteErr
	}
	return c.memConn.CloseWrite()
}

func (c failingConn) Close() error {
	return errors.Join(c.memConn.Close(), c.closeErr)
}

func TestPipeReportsCopyErrors(t *testing.T) {
	t.Parallel()
	writeFailed := errors.New("write failed")
	closeWriteFailed := errors.New("close write failed")
	closeFailed := errors.New("close failed")
	cases := []struct {
		name   string
		target func(memConn) Conn
		want   error
	}{
		{"write error", func(c memConn) Conn { return failingConn{memConn: c, writeErr: writeFailed} }, writeFailed},
		{"short write", func(c memConn) Conn { return failingConn{memConn: c, short: true} }, io.ErrShortWrite},
		{"close write error", func(c memConn) Conn { return failingConn{memConn: c, closeWriteErr: closeWriteFailed} }, closeWriteFailed},
		{"close error after a clean end", func(c memConn) Conn { return failingConn{memConn: c, closeErr: closeFailed} }, closeFailed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				clientApp, clientRelay := memPair()
				targetRelay, targetApp := memPair()
				result := make(chan error, 1)
				go func() { result <- Pipe(t.Context(), clientRelay, c.target(targetRelay), new(Counters), Options{}) }()
				go func() {
					if _, err := io.Copy(io.Discard, targetApp); err != nil {
						return
					}
				}()
				go func() {
					if _, err := io.Copy(io.Discard, clientApp); err != nil {
						return
					}
				}()
				if _, err := clientApp.Write([]byte("data")); err != nil {
					t.Log(err)
				}
				if err := clientApp.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if err := targetApp.CloseWrite(); err != nil {
					t.Fatal(err)
				}
				if err := <-result; !errors.Is(err, c.want) {
					t.Fatalf("Pipe = %v, want %v", err, c.want)
				}
			})
		})
	}
}

func TestPipeReportsReadErrors(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		clientApp, clientRelay := memPair()
		targetRelay, targetApp := memPair()
		result := make(chan error, 1)
		go func() { result <- Pipe(t.Context(), clientRelay, targetRelay, new(Counters), Options{}) }()
		broken := errors.New("reset")
		if err := clientApp.w.CloseWithError(broken); err != nil {
			t.Fatal(err)
		}
		if err := <-result; !errors.Is(err, broken) {
			t.Fatalf("Pipe = %v, want %v", err, broken)
		}
		if err := targetApp.Close(); err != nil {
			t.Fatal(err)
		}
	})
}

func BenchmarkPipe(b *testing.B) {
	clientApp, clientRelay := memPair()
	targetRelay, targetApp := memPair()
	go func() {
		if err := Pipe(context.Background(), clientRelay, targetRelay, new(Counters), Options{}); err != nil {
			return
		}
	}()
	go func() {
		if _, err := io.Copy(io.Discard, targetApp); err != nil {
			return
		}
	}()
	chunk := make([]byte, BufferSize)
	b.SetBytes(int64(len(chunk)))
	b.ReportAllocs()
	for b.Loop() {
		if _, err := clientApp.Write(chunk); err != nil {
			b.Fatal(err)
		}
	}
	if err := errors.Join(clientApp.Close(), targetApp.Close()); err != nil {
		b.Log(err)
	}
}

func TestPipeMaxLifetime(t *testing.T) {
	t.Parallel()
	synctest.Test(t, func(t *testing.T) {
		clientApp, clientRelay := memPair()
		targetRelay, targetApp := memPair()
		defer func() {
			if err := errors.Join(clientApp.Close(), targetApp.Close()); err != nil {
				t.Log(err)
			}
		}()
		go func() {
			if _, err := io.Copy(io.Discard, targetApp); err != nil {
				return
			}
		}()
		stop := make(chan struct{})
		go func() {
			for {
				select {
				case <-stop:
					return
				case <-time.After(time.Second):
				}
				if _, err := clientApp.Write([]byte("x")); err != nil {
					return
				}
			}
		}()
		start := time.Now()
		err := Pipe(t.Context(), clientRelay, targetRelay, new(Counters), Options{IdleTimeout: time.Minute, MaxLifetime: time.Hour})
		close(stop)
		if !errors.Is(err, ErrLifetime) {
			t.Fatalf("Pipe = %v, want ErrLifetime", err)
		}
		if elapsed := time.Since(start); elapsed != time.Hour {
			t.Fatalf("closed after %v of steady traffic, want exactly the lifetime", elapsed)
		}
	})
}
