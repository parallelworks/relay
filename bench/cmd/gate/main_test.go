package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func results(t *testing.T, lines map[string][]float64) string {
	t.Helper()
	var b strings.Builder
	b.WriteString("goos: linux\ngoarch: amd64\npkg: example\n")
	for name, values := range lines {
		for _, v := range values {
			fmt.Fprintf(&b, "Benchmark%s-8 \t 100 \t %g ns/op \t %g MB/s \t 0 allocs/op\n", name, v, 1e3/v)
		}
	}
	path := filepath.Join(t.TempDir(), "bench.txt")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func repeat(v float64) []float64 {
	out := make([]float64, 10)
	for i := range out {
		out[i] = v + float64(i)*v/1000
	}
	return out
}

func TestGate(t *testing.T) {
	t.Parallel()
	steady := map[string][]float64{
		"Throughput/transport=connect-h1/tunnels=1": repeat(100),
		"Throughput/transport=websocket/tunnels=1":  repeat(200),
	}
	cases := []struct {
		name    string
		base    map[string][]float64
		head    map[string][]float64
		wantErr string
	}{
		{"unchanged", steady, steady, ""},
		{"faster", steady, map[string][]float64{
			"Throughput/transport=connect-h1/tunnels=1": repeat(80),
			"Throughput/transport=websocket/tunnels=1":  repeat(200),
		}, ""},
		{"small slowdown", steady, map[string][]float64{
			"Throughput/transport=connect-h1/tunnels=1": repeat(105),
			"Throughput/transport=websocket/tunnels=1":  repeat(200),
		}, ""},
		{"regression", steady, map[string][]float64{
			"Throughput/transport=connect-h1/tunnels=1": repeat(150),
			"Throughput/transport=websocket/tunnels=1":  repeat(200),
		}, "regressed"},
		{"slower than WebSocket", nil, map[string][]float64{
			"Throughput/transport=connect-h1/tunnels=1": repeat(300),
			"Throughput/transport=websocket/tunnels=1":  repeat(200),
		}, "slower than the WebSocket baseline"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			args := []string{"-head", results(t, c.head)}
			if c.base != nil {
				args = append(args, "-base", results(t, c.base))
			}
			var out bytes.Buffer
			err := run(args, &out)
			if c.wantErr == "" && err != nil || c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
				t.Fatalf("run = %v\n%s", err, out.String())
			}
		})
	}
}

func TestGateAllocations(t *testing.T) {
	t.Parallel()
	write := func(allocs int) string {
		var b strings.Builder
		for i := range 10 {
			fmt.Fprintf(&b, "BenchmarkPipe-8 \t 100 \t %d ns/op \t %d allocs/op\n", 100+i, allocs)
		}
		path := filepath.Join(t.TempDir(), "bench.txt")
		if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	err := run([]string{"-base", write(0), "-head", write(1)}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "allocs/op") {
		t.Fatalf("an allocation at steady state passed: %v", err)
	}
}

func TestGateWithoutBase(t *testing.T) {
	t.Parallel()
	head := results(t, map[string][]float64{"X": repeat(1)})
	var out bytes.Buffer
	if err := run([]string{"-head", head, "-base", filepath.Join(t.TempDir(), "missing.txt")}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "skipping") {
		t.Fatalf("output %q", out.String())
	}
}

func TestGateInputErrors(t *testing.T) {
	t.Parallel()
	empty := filepath.Join(t.TempDir(), "empty.txt")
	if err := os.WriteFile(empty, []byte("not a benchmark\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"-head", filepath.Join(t.TempDir(), "missing.txt")},
		{"-head", empty},
		{"-head", results(t, map[string][]float64{"X": repeat(1)}), "-base", empty},
		{"-unknown"},
	} {
		if err := run(args, &bytes.Buffer{}); err == nil {
			t.Errorf("run(%q) succeeded", args)
		}
	}
}
