// Package catalog defines cerberus's distro catalog: the entry schema,
// loading from the embedded catalog plus local override folders, and the
// lint rules every entry must pass.
//
// An entry describes how to find the newest ISO of one distro edition. Its
// steps fetch documents and pull candidates out of them; package resolve
// runs them. Templates in fetch URLs, url, filename, checksum, signature and
// match fields use {name} placeholders, where name matches
// [A-Za-z_][A-Za-z0-9_]*. Other braces, such as regex counts like {64}, are
// left alone. The variable arch is always set. jq programs see variables as
// $name instead, because braces build objects in jq.
package catalog

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/itchyny/gojq"
	"go.yaml.in/yaml/v3"
)

// Category is a use-case group shown in the picker and the README.
type Category struct {
	ID   string
	Name string
}

// Categories lists every valid category, in display order.
var Categories = []Category{
	{"desktop", "Desktop"},
	{"gaming", "Gaming"},
	{"server", "Server"},
	{"homelab", "Homelab"},
	{"containers", "Containers"},
	{"security", "Security and privacy"},
	{"rescue", "Rescue"},
	{"lightweight", "Lightweight"},
	{"diy", "DIY and rolling"},
}

// Architectures lists the architectures cerberus supports. Entry.Arch keys
// must be among them.
var Architectures = []string{"amd64", "arm64"}

// Entry is one maintained ISO: a distro edition, for one or more
// architectures.
type Entry struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Category    string `yaml:"category"`
	Description string `yaml:"description"`
	Homepage    string `yaml:"homepage"`
	// Arch maps cerberus architectures (amd64, arm64) to the distro's own
	// token, which templates see as {arch} and jq as $arch.
	Arch  map[string]string `yaml:"arch"`
	Steps []Step            `yaml:"steps"`
	// URL is the download URL template, rendered after the last step.
	URL string `yaml:"url"`
	// Filename, if set, names the file in the library and must contain
	// {version}. By default the name is the last path segment of URL.
	Filename  string     `yaml:"filename,omitempty"`
	Checksum  *Sidecar   `yaml:"checksum,omitempty"`
	Signature *Signature `yaml:"signature,omitempty"`
	// Keys names armored or binary public keys stored as keys/<name>.asc.
	Keys []string `yaml:"keys,omitempty"`
	// Fingerprints are the key fingerprints allowed to sign, as 40 hex
	// digits. Spaces are ignored and case doesn't matter.
	Fingerprints []string `yaml:"fingerprints,omitempty"`
	// Notes cites where each fingerprint was confirmed.
	Notes string `yaml:"notes,omitempty"`

	// Source is the file the entry came from, for error messages.
	Source string `yaml:"-"`
}

// Values for Step.From.
const (
	FromBody         = "body"
	FromFinalURL     = "final-url"
	FromLastModified = "last-modified"
	FromHeaderPrefix = "header:"
)

// Step fetches one document and extracts candidates from it.
type Step struct {
	// Fetch is the URL template of the document.
	Fetch string `yaml:"fetch"`
	// From selects the text the step reads: "body" (the default),
	// "final-url" (the URL after redirects, fetched with HEAD),
	// "header:<Name>" (that response header, fetched with HEAD), or
	// "last-modified" (that header as a UTC timestamp like
	// 20251018T120000Z, fetched with HEAD).
	From string `yaml:"from,omitempty"`
	// Match is a regular expression with named groups. {name} placeholders
	// are replaced with regexp-quoted variable values before it's compiled.
	// Each match is a candidate whose variables are its non-empty named
	// groups.
	Match string `yaml:"match,omitempty"`
	// JQ is a jq program run over the body parsed as JSON, or as YAML when
	// that fails. Each output must be an object whose values are strings,
	// numbers, booleans or null. Its keys become the candidate's variables,
	// except that null values are skipped, as if the key were absent.
	JQ string `yaml:"jq,omitempty"`
	// Exclude drops candidates whose text it matches. A regex candidate's
	// text is the whole match; a jq candidate's text is its JSON encoding.
	Exclude string `yaml:"exclude,omitempty"`
	// Clearsigned marks a body that is an OpenPGP clearsigned document. It is
	// verified with the entry's keys, and Match or JQ see only the signed
	// text.
	Clearsigned bool `yaml:"clearsigned,omitempty"`
}

// Sidecar fetches the checksum from a file of its own, for entries whose
// steps capture no sha256 or sha512 variable.
type Sidecar struct {
	// Fetch is a URL template; {url} and {filename} are available.
	Fetch string `yaml:"fetch"`
	// Match, if set, is a regex with a sha256 or sha512 group. Otherwise the
	// file is parsed as GNU, BSD or bare checksums, and the line for
	// {filename} is used, or the only line if there's just one.
	Match string `yaml:"match,omitempty"`
}

// Signature types.
const (
	// SigDetachedChecksums is a detached signature over the raw bytes of the
	// document the checksum came from.
	SigDetachedChecksums = "detached-checksums"
	// SigDetachedISO is a detached signature over the ISO itself, checked
	// after the download.
	SigDetachedISO = "detached-iso"
)

// Signature points at a detached OpenPGP signature, binary or armored.
type Signature struct {
	Type string `yaml:"type"`
	// URL is a template; {url} and {filename} are available.
	URL string `yaml:"url"`
}

// Catalog is the merged set of entries and the key files they reference.
type Catalog struct {
	// Entries is ordered by category, as in Categories, then by Name.
	Entries []*Entry
	byID    map[string]*Entry
	keys    map[string][]byte
}

// Load reads every *.yaml file under catalog/ in embedded, then every *.yaml
// file in each override folder in order, skipping folders that don't exist.
// Each file holds a YAML list of entries. An override entry replaces the
// earlier entry with the same ID. Key files come from catalog/keys/*.asc and
// <override>/keys/*.asc, keyed by file name without .asc, later folders
// winning. Load sets each entry's Source, fills Entries, and returns Lint's
// error if the merged catalog is invalid.
func Load(embedded fs.FS, overrideDirs ...string) (*Catalog, error) {
	c := &Catalog{byID: map[string]*Entry{}, keys: map[string][]byte{}}
	// layer and pos record where each ID last landed, so a later layer can
	// replace it while a repeat within one layer stays visible to Lint.
	layer := map[string]int{}
	pos := map[string]int{}
	loadLayer := func(n int, fsys fs.FS, root string, label func(string) string) error {
		files, err := fs.Glob(fsys, path.Join(root, "*.yaml"))
		if err != nil {
			return err
		}
		for _, name := range files {
			data, err := fs.ReadFile(fsys, name)
			if err != nil {
				return err
			}
			source := label(name)
			var list []*Entry
			dec := yaml.NewDecoder(bytes.NewReader(data))
			dec.KnownFields(true)
			if err := dec.Decode(&list); err != nil && !errors.Is(err, io.EOF) {
				return fmt.Errorf("%s: %w", source, err)
			}
			for _, e := range list {
				if e == nil {
					return fmt.Errorf("%s: empty list item", source)
				}
				e.Source = source
				if i, ok := pos[e.ID]; ok && layer[e.ID] < n {
					c.Entries[i] = e
				} else {
					pos[e.ID] = len(c.Entries)
					c.Entries = append(c.Entries, e)
				}
				layer[e.ID] = n
			}
		}
		keys, err := fs.Glob(fsys, path.Join(root, "keys", "*.asc"))
		if err != nil {
			return err
		}
		for _, name := range keys {
			data, err := fs.ReadFile(fsys, name)
			if err != nil {
				return err
			}
			c.keys[strings.TrimSuffix(path.Base(name), ".asc")] = data
		}
		return nil
	}

	if _, err := fs.Stat(embedded, "catalog"); err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	if err := loadLayer(0, embedded, "catalog", func(n string) string { return n }); err != nil {
		return nil, err
	}
	for i, dir := range overrideDirs {
		if _, err := os.Stat(dir); errors.Is(err, fs.ErrNotExist) {
			continue
		}
		label := func(n string) string { return filepath.Join(dir, filepath.FromSlash(n)) }
		if err := loadLayer(i+1, os.DirFS(dir), ".", label); err != nil {
			return nil, err
		}
	}

	// Unknown categories sort last; Lint reports them.
	rank := func(e *Entry) int {
		i := slices.IndexFunc(Categories, func(cat Category) bool { return cat.ID == e.Category })
		if i < 0 {
			return len(Categories)
		}
		return i
	}
	slices.SortStableFunc(c.Entries, func(a, b *Entry) int {
		if ra, rb := rank(a), rank(b); ra != rb {
			return ra - rb
		}
		return strings.Compare(strings.ToLower(a.Name), strings.ToLower(b.Name))
	})
	for _, e := range c.Entries {
		c.byID[e.ID] = e
	}
	if err := Lint(c); err != nil {
		return nil, err
	}
	return c, nil
}

// Get returns the entry with the given ID.
func (c *Catalog) Get(id string) (*Entry, bool) {
	e, ok := c.byID[id]
	return e, ok
}

// InCategory returns one category's entries, in catalog order.
func (c *Catalog) InCategory(category string) []*Entry {
	var out []*Entry
	for _, e := range c.Entries {
		if e.Category == category {
			out = append(out, e)
		}
	}
	return out
}

// KeysFor returns the key material for e.Keys, in order.
func (c *Catalog) KeysFor(e *Entry) ([][]byte, error) {
	out := make([][]byte, 0, len(e.Keys))
	for _, name := range e.Keys {
		k, ok := c.keys[name]
		if !ok {
			return nil, fmt.Errorf("%s: key %q is not in keys/", e.ID, name)
		}
		out = append(out, k)
	}
	return out, nil
}

// Lint checks every entry and returns all problems joined with
// errors.Join, each prefixed with the entry ID and Source. It requires:
//   - IDs matching ^[a-z0-9][a-z0-9-]*$, unique across the catalog;
//   - a non-empty Name, and a Category from Categories;
//   - a non-empty Arch whose keys are in Architectures and whose values
//     match ^[A-Za-z0-9_.-]+$;
//   - at least one step, each with a Fetch starting with https:// or a
//     placeholder, exactly one of Match and JQ, a Match and Exclude that
//     compile once placeholders are replaced, a JQ that parses, and a From
//     that is empty or one of the From values;
//   - a non-empty URL starting with https:// or a placeholder;
//   - a Filename, when set, containing {version};
//   - a Checksum, when set, with a non-empty Fetch and a Match that
//     compiles;
//   - a Signature, when set, of a known Type with a non-empty URL;
//   - Keys and Fingerprints both non-empty when the entry has a Signature
//     or a clearsigned step, and both empty otherwise;
//   - every key name present in the catalog's keys, and every fingerprint
//     40 hex digits once spaces are removed.
func Lint(c *Catalog) error {
	var problems []error
	seen := map[string]bool{}
	for _, e := range c.Entries {
		prefix := fmt.Sprintf("%s (%s): ", e.ID, e.Source)
		for _, msg := range lintEntry(c, e, seen) {
			problems = append(problems, errors.New(prefix+msg))
		}
		seen[e.ID] = true
	}
	return errors.Join(problems...)
}

var (
	idPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	archPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	fprPattern  = regexp.MustCompile(`^[0-9A-Fa-f]{40}$`)
)

// startsHTTPSOrPlaceholder reports whether a URL template begins with
// https:// or a {name} placeholder.
func startsHTTPSOrPlaceholder(s string) bool {
	if strings.HasPrefix(s, "https://") {
		return true
	}
	loc := placeholder.FindStringIndex(s)
	return loc != nil && loc[0] == 0
}

// compiles reports whether regex compiles once every placeholder in it is
// replaced with a harmless value.
func compiles(regex string) error {
	vars := map[string]string{}
	for _, n := range Placeholders(regex) {
		vars[n] = "x"
	}
	re, err := Render(regex, vars, regexp.QuoteMeta)
	if err != nil {
		return err
	}
	_, err = regexp.Compile(re)
	return err
}

func lintEntry(c *Catalog, e *Entry, seen map[string]bool) []string {
	var out []string
	bad := func(format string, args ...any) { out = append(out, fmt.Sprintf(format, args...)) }

	if !idPattern.MatchString(e.ID) {
		bad("id must match %s", idPattern)
	}
	if seen[e.ID] {
		bad("duplicate id")
	}
	if e.Name == "" {
		bad("name is empty")
	}
	if !slices.ContainsFunc(Categories, func(cat Category) bool { return cat.ID == e.Category }) {
		bad("unknown category %q", e.Category)
	}

	if len(e.Arch) == 0 {
		bad("arch is empty")
	}
	for k, v := range e.Arch {
		if !slices.Contains(Architectures, k) {
			bad("unknown architecture %q", k)
		}
		if !archPattern.MatchString(v) {
			bad("arch %s: token %q must match %s", k, v, archPattern)
		}
	}

	if len(e.Steps) == 0 {
		bad("no steps")
	}
	clearsigned := false
	for i, s := range e.Steps {
		n := i + 1
		if !startsHTTPSOrPlaceholder(s.Fetch) {
			bad("step %d: fetch %q must start with https:// or a placeholder", n, s.Fetch)
		}
		switch {
		case s.Match != "" && s.JQ != "":
			bad("step %d: has both match and jq", n)
		case s.Match == "" && s.JQ == "":
			bad("step %d: needs match or jq", n)
		}
		if s.Match != "" {
			if err := compiles(s.Match); err != nil {
				bad("step %d: match: %v", n, err)
			}
		}
		if s.JQ != "" {
			if _, err := gojq.Parse(s.JQ); err != nil {
				bad("step %d: jq: %v", n, err)
			}
		}
		if s.Exclude != "" {
			if err := compiles(s.Exclude); err != nil {
				bad("step %d: exclude: %v", n, err)
			}
		}
		switch name, isHeader := strings.CutPrefix(s.From, FromHeaderPrefix); {
		case s.From == "", s.From == FromBody, s.From == FromFinalURL, s.From == FromLastModified:
		case isHeader && name != "":
		default:
			bad("step %d: unknown from %q", n, s.From)
		}
		clearsigned = clearsigned || s.Clearsigned
	}

	if e.URL == "" {
		bad("url is empty")
	} else if !startsHTTPSOrPlaceholder(e.URL) {
		bad("url %q must start with https:// or a placeholder", e.URL)
	}
	if e.Filename != "" && !strings.Contains(e.Filename, "{version}") {
		bad("filename %q must contain {version}", e.Filename)
	}
	if e.Checksum != nil {
		if e.Checksum.Fetch == "" {
			bad("checksum: fetch is empty")
		}
		if e.Checksum.Match != "" {
			if err := compiles(e.Checksum.Match); err != nil {
				bad("checksum: match: %v", err)
			}
		}
	}
	if e.Signature != nil {
		if e.Signature.Type != SigDetachedChecksums && e.Signature.Type != SigDetachedISO {
			bad("signature: unknown type %q", e.Signature.Type)
		}
		if e.Signature.URL == "" {
			bad("signature: url is empty")
		}
	}

	if signed := e.Signature != nil || clearsigned; signed {
		if len(e.Keys) == 0 || len(e.Fingerprints) == 0 {
			bad("a signature or clearsigned step needs both keys and fingerprints")
		}
	} else if len(e.Keys) > 0 || len(e.Fingerprints) > 0 {
		bad("keys and fingerprints need a signature or a clearsigned step")
	}
	for _, k := range e.Keys {
		if _, ok := c.keys[k]; !ok {
			bad("key %q is not in keys/", k)
		}
	}
	for _, f := range e.Fingerprints {
		if !fprPattern.MatchString(strings.ReplaceAll(f, " ", "")) {
			bad("fingerprint %q is not 40 hex digits", f)
		}
	}
	return out
}

var validFilename = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+~-]*\.iso$`)

// ValidFilename reports whether name is a plain ISO file name cerberus may
// write: no path separators, no leading dot or dash, ending in .iso.
func ValidFilename(name string) bool { return validFilename.MatchString(name) }

var placeholder = regexp.MustCompile(`\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Render replaces each {name} placeholder in tmpl with vars[name], passed
// through quote when quote isn't nil. A placeholder without a variable is an
// error.
func Render(tmpl string, vars map[string]string, quote func(string) string) (string, error) {
	var missing []string
	out := placeholder.ReplaceAllStringFunc(tmpl, func(m string) string {
		v, ok := vars[m[1:len(m)-1]]
		if !ok {
			missing = append(missing, m)
			return m
		}
		if quote != nil {
			return quote(v)
		}
		return v
	})
	if len(missing) > 0 {
		return "", fmt.Errorf("template %q: no value for %s", tmpl, strings.Join(missing, ", "))
	}
	return out, nil
}

// Placeholders returns the variable names tmpl refers to, in order of
// appearance, with repeats.
func Placeholders(tmpl string) []string {
	var names []string
	for _, m := range placeholder.FindAllStringSubmatch(tmpl, -1) {
		names = append(names, m[1])
	}
	return names
}
