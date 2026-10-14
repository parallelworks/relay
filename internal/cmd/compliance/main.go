// Command compliance checks compliance/component-definition.json against the repository and renders
// compliance/README.md from it. With -write it rewrites the README; otherwise it fails when the README
// is stale. With -catalog it also checks every control against an OSCAL NIST SP 800-53 catalog.
package main

import (
	"bytes"
	"cmp"
	"embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"text/template"
	"time"

	"github.com/parallelworks/relay/internal/evidence"
)

const (
	definitionPath = "compliance/component-definition.json"
	readmePath     = "compliance/README.md"
	threatModel    = "THREAT_MODEL.md"
	namespace      = "https://github.com/parallelworks/relay/ns/oscal"
	oscalVersion   = "1.1.3"
)

// required lists the controls the repository plan names.
var required = []string{"ac-17", "au-2", "au-3", "au-12", "cm-7", "ia-5", "sc-8", "sc-13", "sc-23", "si-10", "sr-3", "sr-4"}

// titles are the NIST SP 800-53 Rev 5 control titles, checked against the catalog with -catalog.
var titles = map[string]string{
	"ac-3":  "Access Enforcement",
	"ac-4":  "Information Flow Enforcement",
	"ac-7":  "Unsuccessful Logon Attempts",
	"ac-12": "Session Termination",
	"ac-17": "Remote Access",
	"au-2":  "Event Logging",
	"au-3":  "Content of Audit Records",
	"au-8":  "Time Stamps",
	"au-12": "Audit Record Generation",
	"cm-6":  "Configuration Settings",
	"cm-7":  "Least Functionality",
	"ia-5":  "Authenticator Management",
	"ia-9":  "Service Identification and Authentication",
	"ia-11": "Re-authentication",
	"ra-5":  "Vulnerability Monitoring and Scanning",
	"sa-11": "Developer Testing and Evaluation",
	"sc-5":  "Denial-of-service Protection",
	"sc-7":  "Boundary Protection",
	"sc-8":  "Transmission Confidentiality and Integrity",
	"sc-10": "Network Disconnect",
	"sc-12": "Cryptographic Key Establishment and Management",
	"sc-13": "Cryptographic Protection",
	"sc-23": "Session Authenticity",
	"si-10": "Information Input Validation",
	"si-11": "Error Handling",
	"sr-3":  "Supply Chain Controls and Processes",
	"sr-4":  "Provenance",
	"sr-11": "Component Authenticity",
}

//go:embed README.md.tmpl
var templates embed.FS

var (
	uuidPattern    = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	controlPattern = regexp.MustCompile(`^([a-z]{2})-([1-9]\d*)(?:\.([1-9]\d*))?$`)
)

type document struct {
	ComponentDefinition struct {
		UUID       string      `json:"uuid"`
		Metadata   metadata    `json:"metadata"`
		Components []component `json:"components"`
	} `json:"component-definition"`
}

type metadata struct {
	Title              string    `json:"title"`
	LastModified       time.Time `json:"last-modified"`
	Version            string    `json:"version"`
	OSCALVersion       string    `json:"oscal-version"`
	Roles              []role    `json:"roles"`
	Parties            []party   `json:"parties"`
	ResponsibleParties []parties `json:"responsible-parties"`
}

type role struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

type party struct {
	UUID  string `json:"uuid"`
	Type  string `json:"type"`
	Name  string `json:"name"`
	Links []link `json:"links"`
}

type parties struct {
	RoleID     string   `json:"role-id"`
	PartyUUIDs []string `json:"party-uuids"`
}

type component struct {
	UUID                   string                  `json:"uuid"`
	Type                   string                  `json:"type"`
	Title                  string                  `json:"title"`
	Description            string                  `json:"description"`
	Purpose                string                  `json:"purpose"`
	ResponsibleRoles       []parties               `json:"responsible-roles"`
	ControlImplementations []controlImplementation `json:"control-implementations"`
}

type controlImplementation struct {
	UUID                    string        `json:"uuid"`
	Source                  string        `json:"source"`
	Description             string        `json:"description"`
	ImplementedRequirements []requirement `json:"implemented-requirements"`
}

type requirement struct {
	UUID        string `json:"uuid"`
	ControlID   string `json:"control-id"`
	Description string `json:"description"`
	Props       []prop `json:"props"`
	Links       []link `json:"links"`
	Remarks     string `json:"remarks"`
}

type prop struct {
	Name  string `json:"name"`
	NS    string `json:"ns"`
	Value string `json:"value"`
}

type link struct {
	Href string `json:"href"`
	Rel  string `json:"rel"`
}

// control is one implemented requirement as the README shows it.
type control struct {
	ID, Title, Anchor    string
	Description, Remarks string
	Tests, Mitigations   []string
	Files                []string
}

func main() {
	os.Exit(cli(os.Args[1:], os.DirFS("."), os.WriteFile, os.Stdout, os.Stderr))
}

type writeFunc func(name string, data []byte, perm fs.FileMode) error

func cli(args []string, fsys fs.FS, write writeFunc, out, errOut io.Writer) int {
	flags := flag.NewFlagSet("compliance", flag.ContinueOnError)
	flags.SetOutput(errOut)
	rewrite := flags.Bool("write", false, "rewrite "+readmePath)
	catalogPath := flags.String("catalog", "", "an OSCAL NIST SP 800-53 Rev 5 catalog to check every control against")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if err := run(fsys, write, *rewrite, *catalogPath, out); err != nil {
		if _, werr := fmt.Fprintln(errOut, "compliance:", err); werr != nil {
			return 1
		}
		return 1
	}
	return 0
}

func run(fsys fs.FS, write writeFunc, rewrite bool, catalogPath string, out io.Writer) error {
	controls, err := check(fsys)
	if err != nil {
		return err
	}
	if catalogPath != "" {
		if cerr := checkCatalog(catalogPath, controls); cerr != nil {
			return cerr
		}
	}
	readme, err := render(controls)
	if err != nil {
		return err
	}
	if rewrite {
		if werr := write(readmePath, readme, 0o644); werr != nil {
			return werr
		}
	} else {
		current, rerr := fs.ReadFile(fsys, readmePath)
		if rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			return rerr
		}
		if !bytes.Equal(current, readme) {
			return errors.New(readmePath + " is out of date; run go run ./internal/cmd/compliance -write")
		}
	}
	_, err = fmt.Fprintf(out, "%d controls, each with evidence that exists\n", len(controls))
	return err
}

func check(fsys fs.FS) ([]control, error) {
	data, err := fs.ReadFile(fsys, definitionPath)
	if err != nil {
		return nil, err
	}
	var doc document
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if derr := dec.Decode(&doc); derr != nil {
		return nil, fmt.Errorf("%s: %w", definitionPath, derr)
	}
	def := &doc.ComponentDefinition
	if def.Metadata.OSCALVersion != oscalVersion {
		return nil, fmt.Errorf("oscal-version is %q, want %q", def.Metadata.OSCALVersion, oscalVersion)
	}
	if len(def.Components) != 1 || len(def.Components[0].ControlImplementations) != 1 {
		return nil, errors.New("want one component with one control implementation")
	}
	uuids := []string{def.UUID, def.Components[0].UUID, def.Components[0].ControlImplementations[0].UUID}
	for _, p := range def.Metadata.Parties {
		uuids = append(uuids, p.UUID)
	}
	model, err := mitigationIDs(fsys)
	if err != nil {
		return nil, err
	}

	var controls []control
	var problems []string
	for _, r := range def.Components[0].ControlImplementations[0].ImplementedRequirements {
		uuids = append(uuids, r.UUID)
		c, errs := checkRequirement(fsys, &r, model)
		problems = append(problems, errs...)
		controls = append(controls, c)
	}
	seen := map[string]bool{}
	for _, u := range uuids {
		if !uuidPattern.MatchString(u) {
			problems = append(problems, fmt.Sprintf("uuid %q is not a lowercase version 4 UUID", u))
		}
		if seen[u] {
			problems = append(problems, fmt.Sprintf("uuid %s is used twice", u))
		}
		seen[u] = true
	}
	problems = append(problems, checkControlSet(controls)...)
	if len(problems) > 0 {
		return nil, errors.New(strings.Join(problems, "\n  "))
	}
	return controls, nil
}

func mitigationIDs(fsys fs.FS) (map[string]bool, error) {
	data, err := fs.ReadFile(fsys, threatModel)
	if err != nil {
		return nil, err
	}
	ms, err := evidence.Mitigations(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for _, m := range ms {
		ids[m.ID] = true
	}
	return ids, nil
}

func checkRequirement(fsys fs.FS, r *requirement, model map[string]bool) (c control, problems []string) {
	c = control{ID: r.ControlID, Title: titles[r.ControlID], Description: r.Description, Remarks: r.Remarks}
	fail := func(format string, args ...any) {
		problems = append(problems, r.ControlID+": "+fmt.Sprintf(format, args...))
	}
	if !controlPattern.MatchString(r.ControlID) {
		fail("not a control id")
	}
	if c.Title == "" {
		fail("no title")
	}
	if strings.TrimSpace(r.Description) == "" {
		fail("no description")
	}
	for _, p := range r.Props {
		if p.NS != namespace {
			fail("prop %s has namespace %q", p.Name, p.NS)
			continue
		}
		switch p.Name {
		case "test":
			if err := checkTest(fsys, p.Value); err != nil {
				fail("%v", err)
			}
			c.Tests = append(c.Tests, p.Value)
		case "mitigation":
			if !model[p.Value] {
				fail("mitigation %s is not in %s", p.Value, threatModel)
			}
			c.Mitigations = append(c.Mitigations, p.Value)
		default:
			fail("unknown prop %q", p.Name)
		}
	}
	for _, l := range r.Links {
		name := path.Join(path.Dir(definitionPath), l.Href)
		if l.Rel != "reference" || !fs.ValidPath(name) {
			fail("link %q must be a reference to a file in the repository", l.Href)
			continue
		}
		if _, err := fs.Stat(fsys, name); err != nil {
			fail("link %q: %v", l.Href, err)
			continue
		}
		c.Files = append(c.Files, name)
	}
	if len(c.Tests)+len(c.Mitigations)+len(c.Files) == 0 {
		fail("no evidence")
	}
	return c, problems
}

func checkTest(fsys fs.FS, s string) error {
	ref, err := evidence.ParseRef(s)
	if err != nil {
		return err
	}
	found, err := evidence.HasTest(fsys, ref.Package, ref.Func)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("test %s does not exist", s)
	}
	return nil
}

func checkControlSet(controls []control) []string {
	var problems []string
	ids := map[string]bool{}
	for i := range controls {
		c := &controls[i]
		if ids[c.ID] {
			problems = append(problems, c.ID+": listed twice")
		}
		ids[c.ID] = true
		if i > 0 && compareControls(controls[i-1].ID, c.ID) > 0 {
			problems = append(problems, c.ID+": out of order after "+controls[i-1].ID)
		}
	}
	for _, id := range required {
		if !ids[id] {
			problems = append(problems, id+": required by the plan but missing")
		}
	}
	for id := range titles {
		if !ids[id] {
			problems = append(problems, id+": has a title but no requirement")
		}
	}
	slices.Sort(problems)
	return problems
}

func compareControls(a, b string) int {
	ma, mb := controlPattern.FindStringSubmatch(a), controlPattern.FindStringSubmatch(b)
	if ma == nil || mb == nil {
		return strings.Compare(a, b)
	}
	return cmp.Or(strings.Compare(ma[1], mb[1]), compareNumbers(ma[2], mb[2]), compareNumbers(ma[3], mb[3]))
}

// compareNumbers orders decimal strings without leading zeros by value.
func compareNumbers(a, b string) int {
	return cmp.Or(cmp.Compare(len(a), len(b)), strings.Compare(a, b))
}

type catalogControl struct {
	ID       string           `json:"id"`
	Title    string           `json:"title"`
	Controls []catalogControl `json:"controls"`
}

func checkCatalog(name string, controls []control) error {
	data, err := os.ReadFile(name) //nolint:gosec // G304: the path is the operator's own argument.
	if err != nil {
		return err
	}
	var cat struct {
		Catalog struct {
			Groups []struct {
				Controls []catalogControl `json:"controls"`
			} `json:"groups"`
		} `json:"catalog"`
	}
	if err := json.Unmarshal(data, &cat); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	known := map[string]string{}
	var walk func([]catalogControl)
	walk = func(cs []catalogControl) {
		for _, c := range cs {
			known[c.ID] = c.Title
			walk(c.Controls)
		}
	}
	for _, g := range cat.Catalog.Groups {
		walk(g.Controls)
	}
	var problems []string
	for i := range controls {
		c := &controls[i]
		title, ok := known[c.ID]
		switch {
		case !ok:
			problems = append(problems, c.ID+": not in the catalog")
		case title != c.Title:
			problems = append(problems, fmt.Sprintf("%s: the catalog's title is %q", c.ID, title))
		}
	}
	if len(problems) > 0 {
		return errors.New(strings.Join(problems, "\n  "))
	}
	return nil
}

// display writes a control id as NIST does: ac-17 as AC-17 and sc-8.1 as SC-8(1).
func display(id string) string {
	base, enhancement, ok := strings.Cut(strings.ToUpper(id), ".")
	if ok {
		return base + "(" + enhancement + ")"
	}
	return base
}

// anchor is the fragment GitHub gives a heading.
func anchor(heading string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(heading) {
		switch {
		case r == ' ':
			b.WriteByte('-')
		case r == '-' || 'a' <= r && r <= 'z' || '0' <= r && r <= '9':
			b.WriteRune(r)
		}
	}
	return b.String()
}

func render(controls []control) ([]byte, error) {
	tmpl, err := template.New("README.md.tmpl").Funcs(template.FuncMap{
		"display": display,
		"anchor":  func(c control) string { return anchor(display(c.ID) + " " + c.Title) },
		"rel":     func(name string) string { return "../" + name },
	}).ParseFS(templates, "README.md.tmpl")
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, controls); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
