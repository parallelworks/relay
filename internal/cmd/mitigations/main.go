// Command mitigations fails when a test named in THREAT_MODEL.md is missing from a package that exists.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"strings"
)

type mitigation struct {
	id, pkg, test string
}

var testCell = regexp.MustCompile("^`([a-z0-9_/]+)\\.(Test[A-Za-z0-9_]+)`$")

func main() {
	os.Exit(cli(os.Args[1:], os.DirFS("."), os.Stdout, os.Stderr))
}

func cli(args []string, fsys fs.FS, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("mitigations", flag.ContinueOnError)
	flags.SetOutput(errOut)
	all := flags.Bool("all", false, "fail when a named package does not exist yet")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if err := run(fsys, "THREAT_MODEL.md", *all, out); err != nil {
		if _, werr := io.WriteString(errOut, err.Error()+"\n"); werr != nil {
			return 1
		}
		return 1
	}
	return 0
}

func run(fsys fs.FS, model string, all bool, out io.Writer) error {
	data, err := fs.ReadFile(fsys, model)
	if err != nil {
		return err
	}
	ms, err := parseModel(bytes.NewReader(data))
	if err != nil {
		return err
	}
	var report strings.Builder
	var problems []string
	checked := 0
	for _, m := range ms {
		info, statErr := fs.Stat(fsys, m.pkg)
		if errors.Is(statErr, fs.ErrNotExist) {
			if all {
				problems = append(problems, fmt.Sprintf("%s: package %s does not exist", m.id, m.pkg))
				continue
			}
			fmt.Fprintf(&report, "pending  %s %s.%s\n", m.id, m.pkg, m.test)
			continue
		}
		if statErr != nil {
			return statErr
		}
		if !info.IsDir() {
			problems = append(problems, fmt.Sprintf("%s: %s is not a directory", m.id, m.pkg))
			continue
		}
		found, testErr := hasTest(fsys, m.pkg, m.test)
		if testErr != nil {
			return testErr
		}
		if !found {
			problems = append(problems, fmt.Sprintf("%s: %s has no test %s", m.id, m.pkg, m.test))
			continue
		}
		checked++
		fmt.Fprintf(&report, "ok       %s %s.%s\n", m.id, m.pkg, m.test)
	}
	if _, err = io.WriteString(out, report.String()); err != nil {
		return err
	}
	if len(problems) > 0 {
		return errors.New("missing mitigation tests:\n  " + strings.Join(problems, "\n  "))
	}
	_, err = fmt.Fprintf(out, "%d of %d mitigations have their tests\n", checked, len(ms))
	return err
}

func parseModel(r io.Reader) ([]mitigation, error) {
	var ms []mitigation
	seen := map[string]bool{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if !strings.HasPrefix(line, "| M-") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		id := strings.TrimSpace(cells[0])
		match := testCell.FindStringSubmatch(strings.TrimSpace(cells[len(cells)-1]))
		if match == nil {
			return nil, fmt.Errorf("%s: last column must be `package.TestName`", id)
		}
		if seen[id] {
			return nil, fmt.Errorf("%s: duplicate identifier", id)
		}
		seen[id] = true
		ms = append(ms, mitigation{id: id, pkg: match[1], test: match[2]})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(ms) == 0 {
		return nil, errors.New("no mitigations found")
	}
	return ms, nil
}

func hasTest(fsys fs.FS, dir, name string) (bool, error) {
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
