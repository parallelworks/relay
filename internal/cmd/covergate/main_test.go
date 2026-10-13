package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

const mod = "example.com/m"

func writeProfile(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cover.out")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		profile string
		args    []string
		wantErr string
		wantOut string
	}{
		{
			name: "passes at floor",
			profile: "mode: atomic\n" +
				mod + "/a/a.go:1.1,2.1 9 1\n" +
				mod + "/a/a.go:3.1,4.1 1 0\n",
			wantOut: " 90.0%  a\n",
		},
		{
			name: "fails below floor",
			profile: "mode: atomic\n" +
				mod + "/a/a.go:1.1,2.1 8 1\n" +
				mod + "/a/a.go:3.1,4.1 2 0\n",
			wantErr: "a: 80.0% is below 90.0%",
		},
		{
			name: "duplicate blocks count once and any hit covers",
			profile: "mode: atomic\n" +
				mod + "/a/a.go:1.1,2.1 5 0\n" +
				mod + "/a/a.go:1.1,2.1 5 3\n",
			wantOut: "100.0%  a\n",
		},
		{
			name: "full coverage required for a file",
			profile: "mode: set\n" +
				mod + "/a/a.go:1.1,2.1 99 1\n" +
				mod + "/a/b.go:1.1,2.1 1 0\n",
			args:    []string{"-full", "a/b.go"},
			wantErr: "a/b.go: 0.0% is not full coverage",
		},
		{
			name: "full coverage required for a package",
			profile: "mode: set\n" +
				mod + "/a/a.go:1.1,2.1 1 1\n",
			args:    []string{"-full", " a ,"},
			wantOut: "100.0%  a\n",
		},
		{
			name:    "full coverage target missing",
			profile: "mode: set\n" + mod + "/a/a.go:1.1,2.1 1 1\n",
			args:    []string{"-full", "b"},
			wantErr: "b: required full coverage but it is not in the profile",
		},
		{
			name:    "empty package counts as covered",
			profile: "mode: set\n" + mod + "/a/a.go:1.1,2.1 0 0\n\n",
			wantOut: "100.0%  a\n",
		},
		{name: "empty file", profile: "", wantErr: "empty"},
		{name: "no mode line", profile: "x\n", wantErr: "missing mode line"},
		{name: "no colon", profile: "mode: set\nnocolon\n", wantErr: "malformed profile line"},
		{name: "wrong field count", profile: "mode: set\na.go:1.1,2.1 1\n", wantErr: "malformed profile line"},
		{name: "bad statements", profile: "mode: set\na.go:1.1,2.1 x 1\n", wantErr: "malformed statement count"},
		{name: "bad count", profile: "mode: set\na.go:1.1,2.1 1 x\n", wantErr: "malformed hit count"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var out bytes.Buffer
			args := append([]string{"-profile", writeProfile(t, tt.profile), "-module", mod + "/"}, tt.args...)
			err := run(args, &out)
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

func TestRunErrors(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	if err := run([]string{"-nope"}, &out); err == nil {
		t.Fatal("unknown flag accepted")
	}
	if err := run([]string{"-profile", filepath.Join(t.TempDir(), "missing")}, &out); err == nil {
		t.Fatal("missing profile accepted")
	}
}
