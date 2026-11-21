package catalog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	cerberus "github.com/successful-accident/cerberus"
)

const validEntry = `
- id: demo
  name: Demo
  category: server
  arch: {amd64: x86_64}
  steps:
    - fetch: https://example.com/index
      match: 'v(?P<version>[\d.]+)/{arch}'
  url: https://example.com/{version}/demo-{version}.iso
`

const fingerprint = "0123456789ABCDEF0123456789ABCDEF01234567"

func mapFS(files map[string]string) fstest.MapFS {
	fsys := fstest.MapFS{}
	for name, data := range files {
		fsys[name] = &fstest.MapFile{Data: []byte(data)}
	}
	return fsys
}

func TestLoadRealCatalog(t *testing.T) {
	c, err := Load(cerberus.CatalogFS)
	if err != nil {
		t.Fatalf("embedded catalog: %v", err)
	}
	if len(c.Entries) == 0 {
		t.Fatal("embedded catalog has no entries")
	}
	if _, ok := c.Get("ubuntu-server-lts"); !ok {
		t.Error("ubuntu-server-lts missing")
	}
}

func TestLoadStrictFields(t *testing.T) {
	fsys := mapFS(map[string]string{
		"catalog/typo.yaml": strings.Replace(validEntry, "category:", "catagory:", 1),
	})
	_, err := Load(fsys)
	if err == nil || !strings.Contains(err.Error(), "catalog/typo.yaml") {
		t.Fatalf("want an error naming catalog/typo.yaml, got %v", err)
	}
}

func TestLoadBadYAMLNamesFile(t *testing.T) {
	_, err := Load(mapFS(map[string]string{"catalog/bad.yaml": "- id: [unclosed"}))
	if err == nil || !strings.Contains(err.Error(), "catalog/bad.yaml") {
		t.Fatalf("want an error naming catalog/bad.yaml, got %v", err)
	}
}

func TestLoadMissingCatalogDir(t *testing.T) {
	if _, err := Load(fstest.MapFS{}); err == nil {
		t.Fatal("want an error for an FS without catalog/")
	}
}

func TestLoadEmptyFile(t *testing.T) {
	c, err := Load(mapFS(map[string]string{"catalog/empty.yaml": "# nothing\n", "catalog/a.yaml": validEntry}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(c.Entries))
	}
}

func TestLoadSortsAndSetsSource(t *testing.T) {
	entry := func(id, name, cat string) string {
		return strings.NewReplacer("id: demo", "id: "+id, "name: Demo", "name: "+name, "category: server", "category: "+cat).Replace(validEntry)
	}
	c, err := Load(mapFS(map[string]string{
		"catalog/b.yaml":    entry("z1", "Zeta", "desktop") + entry("s2", "Beta", "server"),
		"catalog/a.yaml":    entry("s1", "Alpha", "server") + entry("l1", "Lite", "lightweight"),
		"catalog/notes.txt": "ignored",
	}))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range c.Entries {
		got = append(got, e.ID)
	}
	if want := "z1 s1 s2 l1"; strings.Join(got, " ") != want {
		t.Errorf("order = %v, want %s", got, want)
	}
	if e, _ := c.Get("s1"); e.Source != "catalog/a.yaml" {
		t.Errorf("Source = %q", e.Source)
	}
	if n := len(c.InCategory("server")); n != 2 {
		t.Errorf("InCategory(server) = %d entries, want 2", n)
	}
}

func TestLoadOverrides(t *testing.T) {
	base := mapFS(map[string]string{
		"catalog/a.yaml":     validEntry,
		"catalog/keys/k.asc": "base-key",
		"catalog/keys/j.asc": "base-j",
	})
	d1, d2 := t.TempDir(), t.TempDir()
	replaced := strings.Replace(validEntry, "name: Demo", "name: Replaced", 1)
	extra := strings.Replace(validEntry, "id: demo", "id: extra", 1)
	write := func(dir, name, data string) {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(d1, "o.yaml", replaced+extra)
	write(d1, "keys/k.asc", "override-key")
	write(d2, "p.yaml", strings.Replace(replaced, "name: Replaced", "name: Twice", 1))

	missing := filepath.Join(t.TempDir(), "nope")
	c, err := Load(base, missing, d1, d2)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(c.Entries))
	}
	e, _ := c.Get("demo")
	if e.Name != "Twice" || e.Source != filepath.Join(d2, "p.yaml") {
		t.Errorf("demo = %q from %q, want the last override", e.Name, e.Source)
	}
	e.Keys = []string{"k", "j"}
	keys, err := c.KeysFor(e)
	if err != nil || string(keys[0]) != "override-key" || string(keys[1]) != "base-j" {
		t.Errorf("KeysFor = %q, %v", keys, err)
	}
}

func TestLoadOverrideErrorNamesFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(p, []byte("- bogus: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Load(mapFS(map[string]string{"catalog/a.yaml": validEntry}), dir)
	if err == nil || !strings.Contains(err.Error(), p) {
		t.Fatalf("want an error naming %s, got %v", p, err)
	}
}

func TestLoadReturnsLintError(t *testing.T) {
	dup := validEntry + validEntry
	_, err := Load(mapFS(map[string]string{"catalog/a.yaml": dup}))
	if err == nil || !strings.Contains(err.Error(), "demo (catalog/a.yaml): duplicate id") {
		t.Fatalf("got %v", err)
	}
}

func TestKeysForMissing(t *testing.T) {
	c, err := Load(mapFS(map[string]string{"catalog/a.yaml": validEntry}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.KeysFor(&Entry{ID: "demo", Keys: []string{"nope"}}); err == nil {
		t.Error("want an error for a missing key")
	}
}

func baseEntry() *Entry {
	return &Entry{
		ID: "demo", Name: "Demo", Category: "server", Source: "x.yaml",
		Arch:  map[string]string{"amd64": "x86_64"},
		Steps: []Step{{Fetch: "https://example.com/", Match: `v(?P<version>\d+)`}},
		URL:   "https://example.com/{version}/demo-{version}.iso",
	}
}

func TestLint(t *testing.T) {
	signed := func(e *Entry) {
		e.Signature = &Signature{Type: SigDetachedChecksums, URL: "https://example.com/sig"}
		e.Keys = []string{"k"}
		e.Fingerprints = []string{fingerprint}
	}
	tests := []struct {
		name   string
		mutate func(*Entry)
		want   string // substring of the error; "" means valid
	}{
		{"valid", func(e *Entry) {}, ""},
		{"valid placeholder fetch and url", func(e *Entry) {
			e.Steps[0].Fetch = "{base}/index"
			e.URL = "{base}/{file}"
		}, ""},
		{"valid regex counts and placeholders", func(e *Entry) {
			e.Steps[0].Match = `(?P<sha256>[0-9a-f]{64}) {arch}-(?P<version>\d+)`
			e.Steps[0].Exclude = `(?i)beta|{arch}`
		}, ""},
		{"valid jq step", func(e *Entry) {
			e.Steps[0].Match = ""
			e.Steps[0].JQ = `.[] | {version, file: .iso}`
		}, ""},
		{"valid from values", func(e *Entry) {
			e.Steps = []Step{
				{Fetch: "https://a/", From: "final-url", Match: `(?P<version>\d+)`},
				{Fetch: "https://a/", From: "last-modified", Match: `(?P<version>\d+)`},
				{Fetch: "https://a/", From: "header:X-Version", Match: `(?P<version>\d+)`},
				{Fetch: "https://a/", From: "body", Match: `(?P<version>\d+)`},
			}
		}, ""},
		{"valid signed", signed, ""},
		{"valid clearsigned step", func(e *Entry) {
			e.Steps[0].Clearsigned = true
			e.Keys = []string{"k"}
			e.Fingerprints = []string{"0123 4567 89ab cdef 0123 4567 89ab cdef 0123 4567"}
		}, ""},
		{"valid checksum sidecar", func(e *Entry) {
			e.Checksum = &Sidecar{Fetch: "{url}.sha256", Match: `(?P<sha256>[0-9a-f]{64}) {filename}`}
		}, ""},

		{"bad id", func(e *Entry) { e.ID = "Demo_1" }, "id must match"},
		{"empty id", func(e *Entry) { e.ID = "" }, "id must match"},
		{"empty name", func(e *Entry) { e.Name = "" }, "name is empty"},
		{"bad category", func(e *Entry) { e.Category = "nope" }, `unknown category "nope"`},
		{"no arch", func(e *Entry) { e.Arch = nil }, "arch is empty"},
		{"bad arch key", func(e *Entry) { e.Arch = map[string]string{"riscv": "r"} }, `unknown architecture "riscv"`},
		{"bad arch value", func(e *Entry) { e.Arch = map[string]string{"amd64": "x/86"} }, "token"},
		{"no steps", func(e *Entry) { e.Steps = nil }, "no steps"},
		{"http fetch", func(e *Entry) { e.Steps[0].Fetch = "http://example.com/" }, "fetch"},
		{"relative fetch", func(e *Entry) { e.Steps[0].Fetch = "example.com/" }, "fetch"},
		{"placeholder not first", func(e *Entry) { e.Steps[0].Fetch = "ftp://{x}" }, "fetch"},
		{"match and jq", func(e *Entry) { e.Steps[0].JQ = ".x" }, "both match and jq"},
		{"neither match nor jq", func(e *Entry) { e.Steps[0].Match = "" }, "needs match or jq"},
		{"bad match", func(e *Entry) { e.Steps[0].Match = `(unclosed` }, "match"},
		{"bad exclude", func(e *Entry) { e.Steps[0].Exclude = `[` }, "exclude"},
		{"bad jq", func(e *Entry) { e.Steps[0].Match = ""; e.Steps[0].JQ = `.[ |` }, "jq"},
		{"bad from", func(e *Entry) { e.Steps[0].From = "cookie" }, `unknown from "cookie"`},
		{"empty header name", func(e *Entry) { e.Steps[0].From = "header:" }, "unknown from"},
		{"empty url", func(e *Entry) { e.URL = "" }, "url is empty"},
		{"http url", func(e *Entry) { e.URL = "http://example.com/x.iso" }, "url"},
		{"filename without version", func(e *Entry) { e.Filename = "demo.iso" }, "{version}"},
		{"checksum without fetch", func(e *Entry) { e.Checksum = &Sidecar{} }, "checksum: fetch"},
		{"checksum bad match", func(e *Entry) { e.Checksum = &Sidecar{Fetch: "https://a/", Match: "("} }, "checksum: match"},
		{"signature unknown type", func(e *Entry) {
			signed(e)
			e.Signature.Type = "magic"
		}, `unknown type "magic"`},
		{"signature without url", func(e *Entry) {
			signed(e)
			e.Signature.URL = ""
		}, "signature: url"},
		{"signature without keys", func(e *Entry) {
			signed(e)
			e.Keys = nil
		}, "needs both keys and fingerprints"},
		{"signature without fingerprints", func(e *Entry) {
			signed(e)
			e.Fingerprints = nil
		}, "needs both keys and fingerprints"},
		{"clearsigned without keys", func(e *Entry) { e.Steps[0].Clearsigned = true }, "needs both keys and fingerprints"},
		{"keys without signature", func(e *Entry) { e.Keys = []string{"k"} }, "need a signature"},
		{"fingerprints without signature", func(e *Entry) { e.Fingerprints = []string{fingerprint} }, "need a signature"},
		{"missing key file", func(e *Entry) {
			signed(e)
			e.Keys = []string{"absent"}
		}, `key "absent" is not in keys/`},
		{"short fingerprint", func(e *Entry) {
			signed(e)
			e.Fingerprints = []string{"ABCD"}
		}, "not 40 hex digits"},
		{"non-hex fingerprint", func(e *Entry) {
			signed(e)
			e.Fingerprints = []string{strings.Repeat("Z", 40)}
		}, "not 40 hex digits"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := baseEntry()
			tc.mutate(e)
			c := &Catalog{Entries: []*Entry{e}, keys: map[string][]byte{"k": []byte("key")}}
			err := Lint(c)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v does not contain %q", err, tc.want)
			}
			if prefix := e.ID + " (x.yaml): "; !strings.HasPrefix(err.Error(), prefix) {
				t.Errorf("error %q lacks prefix %q", err, prefix)
			}
		})
	}
}

func TestLintJoinsAllProblems(t *testing.T) {
	a := baseEntry()
	a.Name = ""
	a.URL = ""
	b := baseEntry()
	b.ID = "other"
	b.Source = "y.yaml"
	b.Category = "nope"
	err := Lint(&Catalog{Entries: []*Entry{a, b}})
	if err == nil {
		t.Fatal("want errors")
	}
	for _, want := range []string{
		"demo (x.yaml): name is empty",
		"demo (x.yaml): url is empty",
		`other (y.yaml): unknown category "nope"`,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in:\n%v", want, err)
		}
	}
}

func TestLintDuplicateIDAcrossFiles(t *testing.T) {
	a, b := baseEntry(), baseEntry()
	b.Source = "y.yaml"
	err := Lint(&Catalog{Entries: []*Entry{a, b}})
	if err == nil || !strings.Contains(err.Error(), "demo (y.yaml): duplicate id") {
		t.Fatalf("got %v", err)
	}
}

func TestRenderPlaceholdersValidFilename(t *testing.T) {
	got, err := Render("a/{x}/{n}{64}", map[string]string{"x": "1.2", "n": "q"}, nil)
	if err != nil || got != "a/1.2/q{64}" {
		t.Errorf("Render = %q, %v", got, err)
	}
	if _, err := Render("{missing}", nil, nil); err == nil {
		t.Error("want an error for a missing variable")
	}
	if got := Placeholders("{a}/{b}/{a}/{1}"); strings.Join(got, ",") != "a,b,a" {
		t.Errorf("Placeholders = %v", got)
	}
	for name, ok := range map[string]bool{
		"debian-12.iso": true, "a.b+c~d.iso": true,
		"../evil.iso": false, ".hidden.iso": false, "-dash.iso": false, "x.img": false, "a/b.iso": false, "": false,
	} {
		if ValidFilename(name) != ok {
			t.Errorf("ValidFilename(%q) = %v, want %v", name, !ok, ok)
		}
	}
}
