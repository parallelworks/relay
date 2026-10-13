package main

import (
	"bytes"
	"os"
	"os/exec"
	"strings"
	"testing"
	"testing/fstest"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

const header = "| ID | Boundary | STRIDE | Threat | Mitigation | Test |\n|---|---|---|---|---|---|\n"

func TestRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		files   fstest.MapFS
		all     bool
		wantErr string
		wantOut string
	}{
		{
			name: "present test passes",
			files: fstest.MapFS{
				"T.md":         {Data: []byte(header + "| M-01 | 1 | S | t | m | `a.TestX` |\n")},
				"a/a_test.go":  {Data: []byte("package a\nfunc TestX(t *testing.T) {}\n")},
				"a/README":     {Data: []byte("x")},
				"a/sub/x.go":   {Data: []byte("package sub")},
				"a/a.go":       {Data: []byte("package a")},
				"a/b_test.go":  {Data: []byte("package a\nfunc (s) TestX() {}\nvar TestY = 1\n")},
				"a/c_test.go":  {Data: []byte("package a\nfunc helper() {}\n")},
				"a/ignored.md": {Data: []byte("TestX")},
			},
			wantOut: "1 of 1 mitigations have their tests",
		},
		{
			name: "missing package is pending",
			files: fstest.MapFS{
				"T.md": {Data: []byte(header + "| M-01 | 1 | S | t | m | `cmd/relay.TestX` |\n")},
			},
			wantOut: "pending  M-01 cmd/relay.TestX",
		},
		{
			name: "missing package fails with all",
			files: fstest.MapFS{
				"T.md": {Data: []byte(header + "| M-01 | 1 | S | t | m | `cmd/relay.TestX` |\n")},
			},
			all:     true,
			wantErr: "M-01: package cmd/relay does not exist",
		},
		{
			name: "missing test fails",
			files: fstest.MapFS{
				"T.md":        {Data: []byte(header + "| M-01 | 1 | S | t | m | `a.TestX` |\n")},
				"a/a_test.go": {Data: []byte("package a\nfunc TestY(t *testing.T) {}\n")},
			},
			wantErr: "M-01: a has no test TestX",
		},
		{
			name: "method with the name does not count",
			files: fstest.MapFS{
				"T.md":        {Data: []byte(header + "| M-01 | 1 | S | t | m | `a.TestX` |\n")},
				"a/a_test.go": {Data: []byte("package a\nfunc (s) TestX() {}\n")},
			},
			wantErr: "has no test TestX",
		},
		{
			name: "package path is a file",
			files: fstest.MapFS{
				"T.md": {Data: []byte(header + "| M-01 | 1 | S | t | m | `a.TestX` |\n")},
				"a":    {Data: []byte("x")},
			},
			wantErr: "M-01: a is not a directory",
		},
		{
			name: "unparseable test file",
			files: fstest.MapFS{
				"T.md":        {Data: []byte(header + "| M-01 | 1 | S | t | m | `a.TestX` |\n")},
				"a/a_test.go": {Data: []byte("not go")},
			},
			wantErr: "expected 'package'",
		},
		{
			name:    "bad test cell",
			files:   fstest.MapFS{"T.md": {Data: []byte(header + "| M-01 | 1 | S | t | m | a.TestX |\n")}},
			wantErr: "M-01: last column must be",
		},
		{
			name: "duplicate id",
			files: fstest.MapFS{"T.md": {Data: []byte(header +
				"| M-01 | 1 | S | t | m | `a.TestX` |\n| M-01 | 1 | S | t | m | `a.TestY` |\n")}},
			wantErr: "M-01: duplicate identifier",
		},
		{
			name:    "no mitigations",
			files:   fstest.MapFS{"T.md": {Data: []byte("# nothing\n")}},
			wantErr: "no mitigations found",
		},
		{
			name:    "missing model",
			files:   fstest.MapFS{},
			wantErr: "file does not exist",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			err := run(tt.files, "T.md", tt.all, &out)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), tt.wantOut) {
				t.Fatalf("output %q does not contain %q", out.String(), tt.wantOut)
			}
		})
	}
}

func TestRepositoryThreatModel(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	if err := run(os.DirFS("../../.."), "THREAT_MODEL.md", false, &out); err != nil {
		t.Fatal(err)
	}
}

func TestClientDependencies(t *testing.T) {
	t.Parallel()
	allowed := []string{"github.com/parallelworks/relay/client", "github.com/parallelworks/relay/dpop", "github.com/go-jose/go-jose/v4"}
	for _, pkg := range []string{"./client", "./dpop"} {
		if _, err := os.Stat("../../../" + pkg); os.IsNotExist(err) {
			continue
		}
		//nolint:gosec // pkg comes from the fixed list above.
		cmd := exec.CommandContext(t.Context(), "go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", pkg)
		cmd.Dir = "../../.."
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list %s: %v", pkg, err)
		}
		for dep := range strings.FieldsSeq(string(out)) {
			ok := false
			for _, a := range allowed {
				if dep == a || strings.HasPrefix(dep, a+"/") {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s depends on %s", pkg, dep)
			}
		}
	}
}

func TestCLI(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{"THREAT_MODEL.md": {Data: []byte(header + "| M-01 | 1 | S | t | m | `a.TestX` |\n")}}
	var out, errOut bytes.Buffer
	if code := cli(nil, fsys, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if code := cli([]string{"-all"}, fsys, &out, &errOut); code != 1 {
		t.Fatalf("exit %d with -all and a missing package", code)
	}
	if code := cli([]string{"-bogus"}, fsys, &out, &errOut); code != 2 {
		t.Fatalf("exit %d for an unknown flag", code)
	}
}
