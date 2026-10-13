// Command gate compares benchmark results and fails on a significant regression. It fails when a
// benchmark is significantly worse than on the base branch by more than -max-regression, and when
// CONNECT over HTTP/1.1 moves fewer bytes per second than the WebSocket baseline.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"golang.org/x/perf/benchfmt"
	"golang.org/x/perf/benchmath"
)

// samples maps a benchmark name and unit to its measurements.
type samples map[string]map[string][]float64

// lowerIsBetter lists the units the gate checks, and which way is better.
var lowerIsBetter = map[string]bool{"sec/op": true, "B/s": false, "allocs/op": true}

const alpha = 0.05

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "gate:", err)
		os.Exit(1)
	}
}

func run(args []string, out io.Writer) error {
	flags := flag.NewFlagSet("gate", flag.ContinueOnError)
	basePath := flags.String("base", "", "results from the base branch; empty or missing skips the comparison")
	headPath := flags.String("head", "", "results from the change")
	maxRegression := flags.Float64("max-regression", 0.10, "largest tolerated significant slowdown, as a fraction")
	if err := flags.Parse(args); err != nil {
		return err
	}
	head, err := load(*headPath)
	if err != nil {
		return err
	}
	var report, failures []string
	if *basePath != "" {
		base, lerr := load(*basePath)
		switch {
		case errors.Is(lerr, os.ErrNotExist):
			report = append(report, "no base results; skipping the regression check")
		case lerr != nil:
			return lerr
		default:
			lines, failed := regressions(base, head, *maxRegression)
			report = append(report, lines...)
			failures = append(failures, failed...)
		}
	}
	lines, failed := belowBaseline(head)
	report = append(report, lines...)
	failures = append(failures, failed...)
	if _, err := io.WriteString(out, strings.Join(report, "\n")+"\n"); err != nil {
		return err
	}
	if len(failures) > 0 {
		return fmt.Errorf("%d check(s) failed:\n  %s", len(failures), strings.Join(failures, "\n  "))
	}
	return nil
}

func load(path string) (s samples, err error) {
	f, err := os.Open(path) //nolint:gosec // G304: the path is the operator's own argument.
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	s = samples{}
	r := benchfmt.NewReader(f, path)
	for r.Scan() {
		res, ok := r.Result().(*benchfmt.Result)
		if !ok {
			continue
		}
		name := string(res.Name.Full())
		if s[name] == nil {
			s[name] = map[string][]float64{}
		}
		for _, v := range res.Values {
			s[name][v.Unit] = append(s[name][v.Unit], v.Value)
		}
	}
	if err := r.Err(); err != nil {
		return nil, err
	}
	if len(s) == 0 {
		return nil, fmt.Errorf("%s: no benchmark results", path)
	}
	return s, nil
}

func names[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func regressions(base, head samples, maxRegression float64) (report, failures []string) {
	for _, name := range names(head) {
		for _, unit := range names(head[name]) {
			lower, checked := lowerIsBetter[unit]
			prior := base[name][unit]
			if !checked || len(prior) == 0 {
				continue
			}
			cmp := compare(prior, head[name][unit])
			worse := cmp.change
			if !lower {
				worse = -worse
			}
			verdict := "~"
			if cmp.significant {
				verdict = fmt.Sprintf("%+.1f%%", cmp.change*100)
			}
			report = append(report, fmt.Sprintf("%-60s %-10s %12.4g -> %12.4g  %s (p=%.3f)", name, unit, cmp.base, cmp.head, verdict, cmp.p))
			if cmp.significant && (worse > maxRegression || (cmp.base == 0 && cmp.head > 0 && lower)) {
				failures = append(failures, fmt.Sprintf("%s %s regressed %+.1f%%", name, unit, cmp.change*100))
			}
		}
	}
	return report, failures
}

type comparison struct {
	base, head  float64
	change      float64
	p           float64
	significant bool
}

func compare(base, head []float64) comparison {
	b := benchmath.NewSample(base, &benchmath.DefaultThresholds)
	h := benchmath.NewSample(head, &benchmath.DefaultThresholds)
	c := comparison{
		base: benchmath.AssumeNothing.Summary(b, 0.95).Center,
		head: benchmath.AssumeNothing.Summary(h, 0.95).Center,
		p:    benchmath.AssumeNothing.Compare(b, h).P,
	}
	if c.base != 0 {
		c.change = (c.head - c.base) / c.base
	}
	c.significant = c.p < alpha && c.base != c.head
	return c
}

// belowBaseline fails when CONNECT over HTTP/1.1 is significantly slower than the WebSocket tunnel
// at the same number of tunnels.
func belowBaseline(head samples) (report, failures []string) {
	for _, name := range names(head) {
		if !strings.Contains(name, "transport=websocket") {
			continue
		}
		ws := head[name]["B/s"]
		connect := head[strings.Replace(name, "transport=websocket", "transport=connect-h1", 1)]["B/s"]
		if len(ws) == 0 || len(connect) == 0 {
			continue
		}
		cmp := compare(ws, connect)
		report = append(report, fmt.Sprintf("%-60s CONNECT/WebSocket throughput %.2fx (p=%.3f)", name, ratio(cmp), cmp.p))
		if cmp.significant && cmp.head < cmp.base {
			failures = append(failures, name+": CONNECT is slower than the WebSocket baseline")
		}
	}
	return report, failures
}

func ratio(c comparison) float64 {
	if c.base == 0 {
		return 0
	}
	return c.head / c.base
}
