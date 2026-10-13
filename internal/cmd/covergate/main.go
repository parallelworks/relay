// Command covergate fails when statement coverage in a Go cover profile falls below a floor.
package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
)

type block struct {
	stmts   int
	covered bool
}

type tally struct {
	stmts, covered int
}

func (t tally) percent() float64 {
	if t.stmts == 0 {
		return 100
	}
	return 100 * float64(t.covered) / float64(t.stmts)
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("covergate", flag.ContinueOnError)
	fs.SetOutput(out)
	profile := fs.String("profile", "coverage.out", "cover profile to read")
	floor := fs.Float64("min", 90, "minimum statement coverage per package, in percent")
	full := fs.String("full", "", "comma-separated package or file paths, relative to the module, that must be fully covered")
	module := fs.String("module", "", "module path to strip from profile paths")
	if err := fs.Parse(args); err != nil {
		return err
	}
	data, err := os.ReadFile(*profile)
	if err != nil {
		return err
	}
	blocks, err := parse(bytes.NewReader(data))
	if err != nil {
		return err
	}
	return evaluate(blocks, strings.TrimSuffix(*module, "/"), *floor, splitList(*full), out)
}

func splitList(s string) []string {
	var out []string
	for item := range strings.SplitSeq(s, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func parse(r io.Reader) (map[string]map[string]block, error) {
	files := map[string]map[string]block{}
	sc := bufio.NewScanner(r)
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			first = false
			if !strings.HasPrefix(line, "mode: ") {
				return nil, errors.New("not a cover profile: missing mode line")
			}
			continue
		}
		if line == "" {
			continue
		}
		file, rest, ok := strings.Cut(line, ":")
		if !ok {
			return nil, fmt.Errorf("malformed profile line %q", line)
		}
		fields := strings.Fields(rest)
		if len(fields) != 3 {
			return nil, fmt.Errorf("malformed profile line %q", line)
		}
		stmts, err := strconv.Atoi(fields[1])
		if err != nil {
			return nil, fmt.Errorf("malformed statement count in %q", line)
		}
		count, err := strconv.Atoi(fields[2])
		if err != nil {
			return nil, fmt.Errorf("malformed hit count in %q", line)
		}
		if files[file] == nil {
			files[file] = map[string]block{}
		}
		b := files[file][fields[0]]
		b.stmts = stmts
		b.covered = b.covered || count > 0
		files[file][fields[0]] = b
	}
	if first {
		return nil, errors.New("not a cover profile: empty")
	}
	return files, sc.Err()
}

func evaluate(files map[string]map[string]block, module string, floor float64, full []string, out io.Writer) error {
	pkgs := map[string]tally{}
	byFile := map[string]tally{}
	for file, blocks := range files {
		rel := strings.TrimPrefix(strings.TrimPrefix(file, module), "/")
		var t tally
		for _, b := range blocks {
			t.stmts += b.stmts
			if b.covered {
				t.covered += b.stmts
			}
		}
		byFile[rel] = t
		p := pkgs[path.Dir(rel)]
		p.stmts += t.stmts
		p.covered += t.covered
		pkgs[path.Dir(rel)] = p
	}
	names := slices.Sorted(maps.Keys(pkgs))
	var report strings.Builder
	var failures []string
	for _, name := range names {
		pct := pkgs[name].percent()
		fmt.Fprintf(&report, "%6.1f%%  %s\n", pct, name)
		if pct < floor {
			failures = append(failures, fmt.Sprintf("%s: %.1f%% is below %.1f%%", name, pct, floor))
		}
	}
	for _, want := range full {
		var t tally
		matched := false
		for rel, ft := range byFile {
			if rel == want || path.Dir(rel) == want {
				matched = true
				t.stmts += ft.stmts
				t.covered += ft.covered
			}
		}
		switch {
		case !matched:
			failures = append(failures, want+": required full coverage but it is not in the profile")
		case t.covered != t.stmts:
			failures = append(failures, fmt.Sprintf("%s: %.1f%% is not full coverage", want, t.percent()))
		}
	}
	if _, err := io.WriteString(out, report.String()); err != nil {
		return err
	}
	if len(failures) > 0 {
		slices.Sort(failures)
		return errors.New("coverage below floor:\n  " + strings.Join(failures, "\n  "))
	}
	return nil
}
