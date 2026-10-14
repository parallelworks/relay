package evidence

import (
	"strings"
	"testing"
	"testing/fstest"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestParseRef(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]Ref{
		"server.TestRejectsTLS12":    {"server", "TestRejectsTLS12"},
		"cmd/relay.FuzzDecodeConfig": {"cmd/relay", "FuzzDecodeConfig"},
	} {
		got, err := ParseRef(in)
		if err != nil || got != want || got.String() != in {
			t.Errorf("ParseRef(%q) = %v, %v", in, got, err)
		}
	}
	for _, in := range []string{"server.BenchmarkX", "TestX", "Server.TestX", "server.TestX()", ""} {
		if _, err := ParseRef(in); err == nil {
			t.Errorf("ParseRef(%q) succeeded", in)
		}
	}
}

const header = "| ID | Boundary | STRIDE | Threat | Mitigation | Test |\n|---|---|---|---|---|---|\n"

func TestMitigations(t *testing.T) {
	t.Parallel()
	ms, err := Mitigations(strings.NewReader("# Model\n\n" + header +
		"| M-01 | 1 | S | t | m | `a.TestX` |\n| M-02 | 1 | S | t | m | `b/c.TestY` |\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 || ms[0] != (Mitigation{"M-01", Ref{"a", "TestX"}}) || ms[1] != (Mitigation{"M-02", Ref{"b/c", "TestY"}}) {
		t.Fatalf("%+v", ms)
	}
	for name, tt := range map[string]struct{ model, err string }{
		"no backticks":   {header + "| M-01 | 1 | S | t | m | a.TestX |\n", "M-01: last column must be"},
		"one backtick":   {header + "| M-01 | 1 | S | t | m | `a.TestX |\n", "M-01: last column must be"},
		"not a test":     {header + "| M-01 | 1 | S | t | m | `a.X` |\n", "M-01: last column must be"},
		"duplicate":      {header + "| M-01 | 1 | S | t | m | `a.TestX` |\n| M-01 | 1 | S | t | m | `a.TestY` |\n", "M-01: duplicate identifier"},
		"no mitigations": {"# nothing\n", "no mitigations found"},
		"line too long":  {"| M-01 " + strings.Repeat("x", 70000) + "\n", "token too long"},
	} {
		if _, err := Mitigations(strings.NewReader(tt.model)); err == nil || !strings.Contains(err.Error(), tt.err) {
			t.Errorf("%s: err = %v, want %q", name, err, tt.err)
		}
	}
}

func TestHasTest(t *testing.T) {
	t.Parallel()
	fsys := fstest.MapFS{
		"a/a_test.go":   {Data: []byte("package a\nfunc TestX(t *testing.T) {}\nfunc FuzzY(f *testing.F) {}\n")},
		"a/b_test.go":   {Data: []byte("package a\nfunc (s) TestM() {}\nvar TestV = 1\nfunc helper() {}\n")},
		"a/a.go":        {Data: []byte("package a\nfunc TestNotInATestFile() {}\n")},
		"a/sub/x.go":    {Data: []byte("package sub")},
		"a/ignored.md":  {Data: []byte("TestX")},
		"bad/x_test.go": {Data: []byte("not go")},
	}
	for name, want := range map[string]bool{"TestX": true, "FuzzY": true, "TestM": false, "TestV": false, "TestNotInATestFile": false} {
		got, err := HasTest(fsys, "a", name)
		if err != nil || got != want {
			t.Errorf("HasTest(a, %s) = %v, %v", name, got, err)
		}
	}
	if _, err := HasTest(fsys, "missing", "TestX"); err == nil {
		t.Error("missing directory")
	}
	if _, err := HasTest(fsys, "bad", "TestX"); err == nil || !strings.Contains(err.Error(), "expected 'package'") {
		t.Errorf("unparseable file: %v", err)
	}
}
