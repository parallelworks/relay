package relaytest

import (
	"io"
	"net"
	"net/http"
	"testing"

	"go.uber.org/goleak"
)

// net/http keeps a connection it closes after a response for a fixed 500 ms, to avoid a TCP reset.
func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m, goleak.IgnoreAnyFunction("net/http.(*conn).closeWriteAndWait"))
}

func TestStartServesTunnels(t *testing.T) {
	t.Parallel()
	for _, nonces := range []bool{false, true} {
		e := Start(t, &Options{Nonces: nonces})
		resp, conn := e.Connect(t.Context(), t, e.Echo.String(), e.AS.Issue(e.Grant(e.Echo)), nonces)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status %d", resp.StatusCode)
		}
		if err := conn.CloseWrite(); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, conn); err != nil {
			t.Fatal(err)
		}
		if err := conn.Close(); err != nil {
			t.Log(err)
		}
	}
}

func TestEchoHalfCloses(t *testing.T) {
	t.Parallel()
	addr := StartEcho(t)
	c, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", addr.String())
	if err != nil {
		t.Fatal(err)
	}
	tc := c.(*net.TCPConn)
	if _, werr := tc.Write([]byte("hi")); werr != nil {
		t.Fatal(werr)
	}
	if cerr := tc.CloseWrite(); cerr != nil {
		t.Fatal(cerr)
	}
	got, err := io.ReadAll(tc)
	if err != nil || string(got) != "hi" {
		t.Fatalf("echo %q, %v", got, err)
	}
	if err := tc.Close(); err != nil {
		t.Fatal(err)
	}
}

type fatalTB struct {
	testing.TB
	failed bool
}

func (f *fatalTB) Helper()      {}
func (f *fatalTB) Fatal(...any) { f.failed = true }

func TestMust(t *testing.T) {
	t.Parallel()
	f := &fatalTB{}
	must(f, nil)
	if f.failed {
		t.Fatal("failed on nil")
	}
	must(f, io.EOF)
	if !f.failed {
		t.Fatal("did not fail on an error")
	}
}

func TestBuffer(t *testing.T) {
	t.Parallel()
	var b Buffer
	if _, err := b.Write([]byte("x")); err != nil || b.String() != "x" {
		t.Fatalf("Buffer = %q, %v", b.String(), err)
	}
}
