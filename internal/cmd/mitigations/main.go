// Command mitigations fails when a test named in THREAT_MODEL.md is missing from a package that exists.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strings"

	"github.com/parallelworks/relay/internal/evidence"
)

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
	ms, err := evidence.Mitigations(bytes.NewReader(data))
	if err != nil {
		return err
	}
	var report strings.Builder
	var problems []string
	checked := 0
	for _, m := range ms {
		info, statErr := fs.Stat(fsys, m.Test.Package)
		if errors.Is(statErr, fs.ErrNotExist) {
			if all {
				problems = append(problems, fmt.Sprintf("%s: package %s does not exist", m.ID, m.Test.Package))
				continue
			}
			fmt.Fprintf(&report, "pending  %s %s.%s\n", m.ID, m.Test.Package, m.Test.Func)
			continue
		}
		if statErr != nil {
			return statErr
		}
		if !info.IsDir() {
			problems = append(problems, fmt.Sprintf("%s: %s is not a directory", m.ID, m.Test.Package))
			continue
		}
		found, testErr := evidence.HasTest(fsys, m.Test.Package, m.Test.Func)
		if testErr != nil {
			return testErr
		}
		if !found {
			problems = append(problems, fmt.Sprintf("%s: %s has no test %s", m.ID, m.Test.Package, m.Test.Func))
			continue
		}
		checked++
		fmt.Fprintf(&report, "ok       %s %s.%s\n", m.ID, m.Test.Package, m.Test.Func)
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
