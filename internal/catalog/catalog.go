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
	"fmt"
	"io/fs"
	"regexp"
	"strings"

	_ "go.yaml.in/yaml/v3" // used by Load
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
	// numbers or booleans; its keys become the candidate's variables.
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
	panic("catalog.Load: not implemented (phase 1)")
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
	panic("catalog.Lint: not implemented (phase 1)")
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
