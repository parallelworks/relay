// Package evidence finds the tests that THREAT_MODEL.md and compliance/ name as proof.
package evidence

import (
	"bufio"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"path"
	"regexp"
	"strings"
)

// Ref names a test or fuzz target as package path and function, such as server.TestRejectsTLS12.
type Ref struct {
	Package, Func string
}

func (r Ref) String() string { return r.Package + "." + r.Func }

var refPattern = regexp.MustCompile(`^([a-z0-9_/]+)\.((?:Test|Fuzz)[A-Za-z0-9_]*)$`)

// ParseRef parses a Ref from "package/path.TestName".
func ParseRef(s string) (Ref, error) {
	m := refPattern.FindStringSubmatch(s)
	if m == nil {
		return Ref{}, fmt.Errorf("%q is not package.TestName", s)
	}
	return Ref{Package: m[1], Func: m[2]}, nil
}

// Mitigation is one row of a threat model's mitigation table.
type Mitigation struct {
	ID   string
	Test Ref
}

// Mitigations reads the mitigation table of a threat model: rows that start with "| M-" and whose
// last cell is a Ref in backticks.
func Mitigations(r io.Reader) ([]Mitigation, error) {
	var ms []Mitigation
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "| M-") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		id := strings.TrimSpace(cells[0])
		last := strings.TrimSpace(cells[len(cells)-1])
		ref, err := ParseRef(strings.TrimSuffix(strings.TrimPrefix(last, "`"), "`"))
		if err != nil || !strings.HasPrefix(last, "`") || !strings.HasSuffix(last, "`") {
			return nil, fmt.Errorf("%s: last column must be `package.TestName`", id)
		}
		if seen[id] {
			return nil, fmt.Errorf("%s: duplicate identifier", id)
		}
		seen[id] = true
		ms = append(ms, Mitigation{ID: id, Test: ref})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(ms) == 0 {
		return nil, errors.New("no mitigations found")
	}
	return ms, nil
}

// HasTest reports whether a _test.go file in dir declares the top-level function name.
func HasTest(fsys fs.FS, dir, name string) (bool, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return false, err
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := fs.ReadFile(fsys, path.Join(dir, e.Name()))
		if err != nil {
			return false, err
		}
		file, err := parser.ParseFile(fset, e.Name(), src, parser.SkipObjectResolution)
		if err != nil {
			return false, err
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == name {
				return true, nil
			}
		}
	}
	return false, nil
}
