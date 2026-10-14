package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func noWrite(string, []byte, fs.FileMode) error { return errors.New("unexpected write") }

func TestRepositoryCompliance(t *testing.T) {
	t.Parallel()
	var out bytes.Buffer
	if err := run(os.DirFS("../../.."), noWrite, false, "", &out); err != nil {
		t.Fatal(err)
	}
}

const model = "| ID | B | S | T | M | Test |\n|---|---|---|---|---|---|\n| M-01 | 1 | S | t | m | `a.TestX` |\n"

func requirementJSON(id string, extra map[string]any) map[string]any {
	r := map[string]any{
		"uuid":        fmt.Sprintf("00000000-0000-4000-8000-%012x", crc32.ChecksumIEEE([]byte(id))),
		"control-id":  id,
		"description": "does " + id,
		"props":       []any{map[string]any{"name": "mitigation", "ns": namespace, "value": "M-01"}},
	}
	for k, v := range extra {
		if v == nil {
			delete(r, k)
		} else {
			r[k] = v
		}
	}
	return r
}

// repo builds a repository whose definition covers every titled control, then applies edit to the
// requirement list.
func repo(t *testing.T, edit func([]map[string]any) []map[string]any) fstest.MapFS {
	t.Helper()
	ids := make([]string, 0, len(titles))
	for id := range titles {
		ids = append(ids, id)
	}
	slices.SortFunc(ids, compareControls)
	reqs := make([]map[string]any, len(ids))
	for i, id := range ids {
		reqs[i] = requirementJSON(id, nil)
	}
	if edit != nil {
		reqs = edit(reqs)
	}
	doc := map[string]any{"component-definition": map[string]any{
		"uuid": "11111111-1111-4111-8111-111111111111",
		"metadata": map[string]any{
			"title": "relay", "last-modified": "2026-01-01T00:00:00Z", "version": "1", "oscal-version": oscalVersion,
			"parties": []any{map[string]any{"uuid": "22222222-2222-4222-8222-222222222222", "type": "organization", "name": "o"}},
		},
		"components": []any{map[string]any{
			"uuid": "33333333-3333-4333-8333-333333333333", "type": "software", "title": "relay", "description": "d", "purpose": "p",
			"control-implementations": []any{map[string]any{
				"uuid": "44444444-4444-4444-8444-444444444444", "source": "s", "description": "d",
				"implemented-requirements": reqs,
			}},
		}},
	}}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return fstest.MapFS{
		definitionPath:    {Data: data},
		threatModel:       {Data: []byte(model)},
		"a/a_test.go":     {Data: []byte("package a\nfunc TestX(t *testing.T) {}\n")},
		"server/x.go":     {Data: []byte("package server\n")},
		"bad/bad_test.go": {Data: []byte("not go")},
	}
}

func setAC3(extra map[string]any) func([]map[string]any) []map[string]any {
	return func(reqs []map[string]any) []map[string]any {
		for i, r := range reqs {
			if r["control-id"] == "ac-3" {
				reqs[i] = requirementJSON("ac-3", extra)
			}
		}
		return reqs
	}
}

func TestCheck(t *testing.T) {
	t.Parallel()
	good := repo(t, setAC3(map[string]any{
		"props": []any{
			map[string]any{"name": "test", "ns": namespace, "value": "a.TestX"},
			map[string]any{"name": "mitigation", "ns": namespace, "value": "M-01"},
		},
		"links":   []any{map[string]any{"href": "../server/x.go", "rel": "reference"}},
		"remarks": "the owner does more",
	}))
	controls, err := check(good)
	if err != nil {
		t.Fatal(err)
	}
	if c := controls[0]; c.ID != "ac-3" || c.Tests[0] != "a.TestX" || c.Mitigations[0] != "M-01" || c.Files[0] != "server/x.go" || c.Remarks == "" {
		t.Fatalf("%+v", c)
	}

	tests := map[string]struct {
		fsys fstest.MapFS
		want string
	}{
		"missing test":   {repo(t, setAC3(map[string]any{"props": []any{map[string]any{"name": "test", "ns": namespace, "value": "a.TestY"}}})), "ac-3: test a.TestY does not exist"},
		"bad test ref":   {repo(t, setAC3(map[string]any{"props": []any{map[string]any{"name": "test", "ns": namespace, "value": "TestY"}}})), "is not package.TestName"},
		"unparseable":    {repo(t, setAC3(map[string]any{"props": []any{map[string]any{"name": "test", "ns": namespace, "value": "bad.TestY"}}})), "expected 'package'"},
		"no package":     {repo(t, setAC3(map[string]any{"props": []any{map[string]any{"name": "test", "ns": namespace, "value": "nope.TestY"}}})), "file does not exist"},
		"mitigation":     {repo(t, setAC3(map[string]any{"props": []any{map[string]any{"name": "mitigation", "ns": namespace, "value": "M-99"}}})), "mitigation M-99 is not in"},
		"namespace":      {repo(t, setAC3(map[string]any{"props": []any{map[string]any{"name": "test", "ns": "x", "value": "a.TestX"}}})), `has namespace "x"`},
		"prop name":      {repo(t, setAC3(map[string]any{"props": []any{map[string]any{"name": "other", "ns": namespace, "value": "v"}}})), `unknown prop "other"`},
		"no evidence":    {repo(t, setAC3(map[string]any{"props": nil})), "ac-3: no evidence"},
		"description":    {repo(t, setAC3(map[string]any{"description": " "})), "ac-3: no description"},
		"missing file":   {repo(t, setAC3(map[string]any{"links": []any{map[string]any{"href": "../nope.go", "rel": "reference"}}})), `link "../nope.go"`},
		"escape":         {repo(t, setAC3(map[string]any{"links": []any{map[string]any{"href": "../../x", "rel": "reference"}}})), "must be a reference to a file in the repository"},
		"rel":            {repo(t, setAC3(map[string]any{"links": []any{map[string]any{"href": "../server/x.go", "rel": "related"}}})), "must be a reference"},
		"uuid":           {repo(t, setAC3(map[string]any{"uuid": "not-a-uuid"})), `uuid "not-a-uuid" is not`},
		"duplicate uuid": {repo(t, setAC3(map[string]any{"uuid": "11111111-1111-4111-8111-111111111111"})), "is used twice"},
		"untitled": {repo(t, func(r []map[string]any) []map[string]any {
			return append(r, requirementJSON("zz-1", nil))
		}), "zz-1: no title"},
		"bad id": {repo(t, func(r []map[string]any) []map[string]any {
			return append(r, requirementJSON("AC-3", nil))
		}), "AC-3: not a control id"},
		"duplicate": {repo(t, func(r []map[string]any) []map[string]any {
			return append(r, requirementJSON("sr-11", nil))
		}), "sr-11: listed twice"},
		"order": {repo(t, func(r []map[string]any) []map[string]any {
			r[0], r[1] = r[1], r[0]
			return r
		}), "ac-3: out of order after ac-4"},
		"required": {repo(t, func(r []map[string]any) []map[string]any {
			return r[:len(r)-1]
		}), "sr-11: has a title but no requirement"},
		"plan": {repo(t, func(r []map[string]any) []map[string]any {
			return slices.DeleteFunc(r, func(m map[string]any) bool { return m["control-id"] == "ac-17" })
		}), "ac-17: required by the plan but missing"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := check(tt.fsys); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestCheckDocument(t *testing.T) {
	t.Parallel()
	base := repo(t, nil)
	edit := func(f func(doc map[string]any)) fstest.MapFS {
		var doc map[string]any
		if err := json.Unmarshal(base[definitionPath].Data, &doc); err != nil {
			t.Fatal(err)
		}
		f(doc["component-definition"].(map[string]any))
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		fsys := maps.Clone(base)
		fsys[definitionPath] = &fstest.MapFile{Data: data}
		return fsys
	}
	for name, tt := range map[string]struct {
		fsys fstest.MapFS
		want string
	}{
		"version":    {edit(func(d map[string]any) { d["metadata"].(map[string]any)["oscal-version"] = "1.0.0" }), `oscal-version is "1.0.0"`},
		"unknown":    {edit(func(d map[string]any) { d["extra"] = 1 }), `unknown field "extra"`},
		"components": {edit(func(d map[string]any) { d["components"] = []any{} }), "want one component"},
		"definition": {fstest.MapFS{}, "file does not exist"},
		"model": {func() fstest.MapFS {
			f := edit(func(map[string]any) {})
			delete(f, threatModel)
			return f
		}(), "THREAT_MODEL.md: file does not exist"},
		"bad model": {func() fstest.MapFS {
			f := edit(func(map[string]any) {})
			f[threatModel] = &fstest.MapFile{Data: []byte("# none\n")}
			return f
		}(), "no mitigations found"},
	} {
		if _, err := check(tt.fsys); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tt.want)
		}
	}
}

func catalog(t *testing.T, edit func(map[string]string)) string {
	t.Helper()
	known := maps.Clone(titles)
	if edit != nil {
		edit(known)
	}
	var controls []any
	for id, title := range known {
		controls = append(controls, map[string]any{"id": id, "title": title, "controls": []any{map[string]any{"id": id + ".1", "title": "enhancement"}}})
	}
	data, err := json.Marshal(map[string]any{"catalog": map[string]any{"groups": []any{map[string]any{"controls": controls}}}})
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return name
}

func TestRun(t *testing.T) {
	t.Parallel()
	fsys := repo(t, nil)
	var written []byte
	write := func(name string, data []byte, _ fs.FileMode) error {
		if name != readmePath {
			t.Errorf("wrote %s", name)
		}
		written = data
		return nil
	}
	var out bytes.Buffer
	if err := run(fsys, write, true, catalog(t, nil), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "controls, each with evidence") || !bytes.Contains(written, []byte("## AC-17 Remote Access")) {
		t.Fatalf("%s\n%s", out.String(), written)
	}
	if err := run(fsys, noWrite, false, "", &out); err == nil || !strings.Contains(err.Error(), "out of date") {
		t.Fatalf("missing README: %v", err)
	}
	fsys[readmePath] = &fstest.MapFile{Data: written}
	if err := run(fsys, noWrite, false, "", &out); err != nil {
		t.Fatal(err)
	}
	fsys[readmePath] = &fstest.MapFile{Data: append(written, '\n')}
	if err := run(fsys, noWrite, false, "", &out); err == nil {
		t.Fatal("stale README accepted")
	}
	if err := run(fsys, func(string, []byte, fs.FileMode) error { return errors.New("disk full") }, true, "", &out); err == nil || err.Error() != "disk full" {
		t.Fatalf("write error: %v", err)
	}
	if err := run(fstest.MapFS{}, noWrite, false, "", &out); err == nil {
		t.Fatal("empty repository accepted")
	}
	fsys[readmePath] = &fstest.MapFile{Mode: fs.ModeDir}
	if err := run(fsys, noWrite, false, "", &out); err == nil {
		t.Fatal("unreadable README accepted")
	}
}

func TestCatalog(t *testing.T) {
	t.Parallel()
	controls, err := check(repo(t, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := checkCatalog(catalog(t, nil), controls); err != nil {
		t.Fatal(err)
	}
	for name, tt := range map[string]struct {
		path string
		want string
	}{
		"missing": {catalog(t, func(k map[string]string) { delete(k, "sr-4") }), "sr-4: not in the catalog"},
		"title":   {catalog(t, func(k map[string]string) { k["sr-4"] = "Origin" }), `sr-4: the catalog's title is "Origin"`},
		"file":    {filepath.Join(t.TempDir(), "none.json"), "no such file"},
	} {
		if err := checkCatalog(tt.path, controls); err == nil || !strings.Contains(err.Error(), tt.want) {
			t.Errorf("%s: err = %v, want %q", name, err, tt.want)
		}
	}
	bad := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkCatalog(bad, controls); err == nil {
		t.Error("malformed catalog accepted")
	}
}

func TestDisplayAndAnchor(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"ac-17": "AC-17", "sc-8.1": "SC-8(1)"} {
		if got := display(in); got != want {
			t.Errorf("display(%s) = %s", in, got)
		}
	}
	if got := anchor("SC-5 Denial-of-service Protection (x)"); got != "sc-5-denial-of-service-protection-x" {
		t.Errorf("anchor = %s", got)
	}
	for _, tt := range []struct {
		a, b string
		want int
	}{{"ac-3", "ac-12", -1}, {"sc-8", "sc-8.1", -1}, {"sc-8.2", "sc-8.10", -1}, {"au-2", "ac-17", 1}, {"x", "y", -1}, {"ac-1", "ac-1", 0}} {
		if got := compareControls(tt.a, tt.b); got != tt.want {
			t.Errorf("compareControls(%s, %s) = %d", tt.a, tt.b, got)
		}
	}
}

func TestCLI(t *testing.T) {
	t.Parallel()
	var out, errOut bytes.Buffer
	if code := cli([]string{"-bogus"}, fstest.MapFS{}, noWrite, &out, &errOut); code != 2 {
		t.Fatalf("exit %d for an unknown flag", code)
	}
	if code := cli(nil, fstest.MapFS{}, noWrite, &out, &errOut); code != 1 || !strings.Contains(errOut.String(), "compliance:") {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if code := cli(nil, os.DirFS("../../.."), noWrite, &out, &errOut); code != 0 {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
}
