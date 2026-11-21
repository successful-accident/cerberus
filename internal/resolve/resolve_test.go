package resolve

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/successful-accident/cerberus/internal/catalog"
	"github.com/successful-accident/cerberus/internal/download"
)

// ---- fakes ----

type page struct {
	body   string
	header http.Header
	final  string
}

type fakeFetcher struct {
	pages map[string]page
	gets  []string
	heads []string
	onGet func(url string) error
}

func (f *fakeFetcher) Get(ctx context.Context, u string) (*download.Doc, error) {
	f.gets = append(f.gets, u)
	if f.onGet != nil {
		if err := f.onGet(u); err != nil {
			return nil, err
		}
	}
	p, ok := f.pages[u]
	if !ok {
		return nil, fmt.Errorf("GET %s: 404 Not Found", u)
	}
	return &download.Doc{Status: 200, Body: []byte(p.body), FinalURL: u, Header: p.header}, nil
}

func (f *fakeFetcher) Head(ctx context.Context, u string) (*download.Doc, error) {
	f.heads = append(f.heads, u)
	p, ok := f.pages[u]
	if !ok {
		return nil, fmt.Errorf("HEAD %s: 404 Not Found", u)
	}
	final := p.final
	if final == "" {
		final = u
	}
	return &download.Doc{Status: 200, FinalURL: final, Header: p.header}, nil
}

func pages(kv ...string) *fakeFetcher {
	f := &fakeFetcher{pages: map[string]page{}}
	for i := 0; i < len(kv); i += 2 {
		f.pages[kv[i]] = page{body: kv[i+1]}
	}
	return f
}

const (
	beginMark = "-----BEGIN SIGNED-----"
	endMark   = "-----END SIGNED-----"
)

// fakeVerifier accepts the detached signature "GOOD:" + hex sha256(data), and
// clearsigned documents that hold a signed block between two marker lines.
type fakeVerifier struct{}

func goodSig(data string) string {
	sum := sha256.Sum256([]byte(data))
	return "GOOD:" + hex.EncodeToString(sum[:])
}

func (fakeVerifier) VerifyDetached(data, sig []byte) (string, error) {
	if string(sig) != goodSig(string(data)) {
		return "", errors.New("bad detached signature")
	}
	return "DETACHED-FPR", nil
}

func (fakeVerifier) VerifyClearsigned(doc []byte) ([]byte, string, error) {
	s := string(doc)
	_, rest, ok := strings.Cut(s, beginMark+"\n")
	if !ok {
		return nil, "", errors.New("no signature")
	}
	plain, _, ok := strings.Cut(rest, endMark)
	if !ok {
		return nil, "", errors.New("unterminated signature")
	}
	return []byte(plain), "CLEAR-FPR", nil
}

func hexOf(c byte, n int) string { return strings.Repeat(string(c), n) }

func h256(c byte) string { return hexOf(c, 64) }
func h512(c byte) string { return hexOf(c, 128) }

func mustResolve(t *testing.T, f Fetcher, e *catalog.Entry, opt Options) *Release {
	t.Helper()
	rel, err := Resolve(context.Background(), f, e, opt)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return rel
}

func wantError(t *testing.T, f Fetcher, e *catalog.Entry, opt Options, substr string) {
	t.Helper()
	rel, err := Resolve(context.Background(), f, e, opt)
	if err == nil {
		t.Fatalf("Resolve succeeded with %+v, want an error containing %q", rel, substr)
	}
	if !strings.Contains(err.Error(), substr) {
		t.Fatalf("error %q does not contain %q", err, substr)
	}
}

// ---- entries ----

const site = "https://releases.example.com/"

// ubuntuEntry is modeled on the Ubuntu Server entry in catalog/server.yaml.
func ubuntuEntry() *catalog.Entry {
	return &catalog.Entry{
		ID:   "ubuntu",
		Arch: map[string]string{"amd64": "amd64"},
		Steps: []catalog.Step{
			{Fetch: site, Match: `href="(?P<version>\d[02468]\.04(?:\.\d+)?)/"`},
			{
				Fetch: site + "{version}/SHA256SUMS",
				Match: `(?m)^(?P<sha256>[0-9a-f]{64}) \*(?P<file>ubuntu-(?P<version>[\d.]+)-live-server-{arch}\.iso)$`,
			},
		},
		URL: site + "{version}/{file}",
	}
}

func ubuntuSums(version string, hash string) string {
	return fmt.Sprintf("%s *ubuntu-%s-desktop-amd64.iso\n%s *ubuntu-%s-live-server-amd64.iso\n%s *ubuntu-%s-live-server-arm64.iso\n",
		h256('f'), version, hash, version, h256('e'), version)
}

func ubuntuFetcher() *fakeFetcher {
	return pages(
		site, `<a href="22.04.5/">22.04.5</a> <a href="24.04.2/">x</a> <a href="24.04.3/">x</a> <a href="24.04.3/">again</a> <a href="25.10/">no</a> <a href="26.04.1/">x</a> <a href="../">up</a>`,
		site+"22.04.5/SHA256SUMS", ubuntuSums("22.04.5", h256('1')),
		site+"24.04.2/SHA256SUMS", ubuntuSums("24.04.2", h256('2')),
		site+"24.04.3/SHA256SUMS", ubuntuSums("24.04.3", h256('3')),
		site+"26.04.1/SHA256SUMS", ubuntuSums("26.04.1", h256('6')),
	)
}

// ---- tests ----

func TestTwoStepResolution(t *testing.T) {
	f := ubuntuFetcher()
	rel := mustResolve(t, f, ubuntuEntry(), Options{Arch: "amd64"})
	want := Release{
		EntryID:  "ubuntu",
		Version:  "26.04.1",
		URL:      site + "26.04.1/ubuntu-26.04.1-live-server-amd64.iso",
		Filename: "ubuntu-26.04.1-live-server-amd64.iso",
	}
	if rel.EntryID != want.EntryID || rel.Version != want.Version || rel.URL != want.URL || rel.Filename != want.Filename {
		t.Errorf("got %+v, want %+v", rel, want)
	}
	if rel.Checksum.String() != "sha256:"+h256('6') {
		t.Errorf("checksum = %v", rel.Checksum)
	}
	if rel.SignedBy != "" || rel.ISOSignatureURL != "" {
		t.Errorf("unsigned entry has SignedBy %q, ISOSignatureURL %q", rel.SignedBy, rel.ISOSignatureURL)
	}
	if rel.Vars["arch"] != "amd64" || rel.Vars["file"] != rel.Filename || rel.Vars["version"] != "26.04.1" {
		t.Errorf("Vars = %v", rel.Vars)
	}
	if got := len(f.gets); got != 2 {
		t.Errorf("fetched %d documents, want 2: %v", got, f.gets)
	}
}

func TestVarsIsACopy(t *testing.T) {
	e := ubuntuEntry()
	rel := mustResolve(t, ubuntuFetcher(), e, Options{Arch: "amd64"})
	rel.Vars["version"] = "tampered"
	if again := mustResolve(t, ubuntuFetcher(), e, Options{Arch: "amd64"}); again.Vars["version"] != "26.04.1" {
		t.Error("Vars is shared between resolutions")
	}
}

func TestPin(t *testing.T) {
	for pin, want := range map[string]string{
		"":        "26.04.1",
		"24":      "24.04.3",
		"24.04":   "24.04.3",
		"24.04.2": "24.04.2",
		"22.04":   "22.04.5",
		"22.04.5": "22.04.5",
	} {
		rel := mustResolve(t, ubuntuFetcher(), ubuntuEntry(), Options{Arch: "amd64", Pin: pin})
		if rel.Version != want {
			t.Errorf("pin %q: version %s, want %s", pin, rel.Version, want)
		}
	}
	wantError(t, ubuntuFetcher(), ubuntuEntry(), Options{Arch: "amd64", Pin: "20.04"}, "step 1: no candidates")
	// 24.0 must not match 24.04: the pin ends mid-number.
	wantError(t, ubuntuFetcher(), ubuntuEntry(), Options{Arch: "amd64", Pin: "24.0"}, "no candidates")
}

func TestArchSelectsToken(t *testing.T) {
	e := ubuntuEntry()
	e.Arch["arm64"] = "arm64"
	f := ubuntuFetcher()
	rel := mustResolve(t, f, e, Options{Arch: "arm64"})
	if rel.Filename != "ubuntu-26.04.1-live-server-arm64.iso" || rel.Checksum.Hex != h256('e') {
		t.Errorf("got %s %v", rel.Filename, rel.Checksum)
	}
}

func TestMissingArchAndUnknownPlaceholder(t *testing.T) {
	f := ubuntuFetcher()
	wantError(t, f, ubuntuEntry(), Options{Arch: "arm64"}, `no architecture "arm64"`)
	if len(f.gets) != 0 {
		t.Errorf("fetched %v before failing", f.gets)
	}

	for name, mutate := range map[string]func(*catalog.Entry){
		"fetch": func(e *catalog.Entry) { e.Steps[0].Fetch = site + "{nope}/" },
		"match": func(e *catalog.Entry) { e.Steps[0].Match = `{nope}` },
		"url":   func(e *catalog.Entry) { e.URL = site + "{nope}" },
		// {file} isn't known until the second step has run.
		"exclude": func(e *catalog.Entry) { e.Steps[0].Exclude = `{file}` },
	} {
		e := ubuntuEntry()
		mutate(e)
		t.Run(name, func(t *testing.T) {
			wantError(t, ubuntuFetcher(), e, Options{Arch: "amd64"}, "no value for")
		})
	}
}

func TestExclude(t *testing.T) {
	feed := `v2.0-beta1 v1.9 v1.8-rc1 v1.8`
	step := func(exclude string) *catalog.Entry {
		return &catalog.Entry{
			ID:   "demo",
			Arch: map[string]string{"amd64": "beta"},
			Steps: []catalog.Step{
				{Fetch: site + "list", Match: `v(?P<version>[\d.]+(?:-[a-z]+\d*)?)`, Exclude: exclude},
				{Fetch: site + "{version}/sum", Match: `(?P<sha256>[0-9a-f]{64})`},
			},
			URL:      site + "{version}/demo.iso",
			Filename: "demo-{version}.iso",
		}
	}
	f := func() *fakeFetcher {
		return pages(site+"list", feed,
			site+"2.0-beta1/sum", h256('2'), site+"1.9/sum", h256('9'),
			site+"1.8-rc1/sum", h256('8'), site+"1.8/sum", h256('7'))
	}
	for _, tc := range []struct{ exclude, want string }{
		{"", "2.0-beta1"},
		{"beta", "1.9"},
		{`-(beta|rc)`, "1.9"},
		{`(beta|rc|1\.9)`, "1.8"},
		{`v{arch}`, "2.0-beta1"}, // a placeholder is quoted, not interpreted: "vbeta" matches nothing
		{`-{arch}`, "1.9"},
	} {
		rel := mustResolve(t, f(), step(tc.exclude), Options{Arch: "amd64"})
		if rel.Version != tc.want {
			t.Errorf("exclude %q: version %s, want %s", tc.exclude, rel.Version, tc.want)
		}
	}
	wantError(t, f(), step(`.`), Options{Arch: "amd64"}, "step 1: no candidates")
}

func TestJQOverJSON(t *testing.T) {
	feed := `[
	  {"version": "3.1", "file": "tool-3.1.iso", "sha256": "` + h256('a') + `", "channel": "stable", "build": 20261115},
	  {"version": "3.2", "file": "tool-3.2.iso", "sha256": "` + h256('b') + `", "channel": "beta", "build": 20261201},
	  {"version": "3.10", "file": "tool-3.10.iso", "sha256": "` + h256('c') + `", "channel": "stable", "build": 20261220}
	]`
	e := &catalog.Entry{
		ID:   "tool",
		Arch: map[string]string{"amd64": "x64"},
		Steps: []catalog.Step{{
			Fetch: site + "feed.json",
			JQ:    `.[] | select(.file | contains($arch) | not) | {version, file, sha256, channel, build}`,
		}},
		URL: site + "{file}",
	}
	// "x64" is in no file name, so every entry passes the select.
	f := pages(site+"feed.json", feed)
	rel := mustResolve(t, f, e, Options{Arch: "amd64"})
	if rel.Version != "3.10" || rel.Filename != "tool-3.10.iso" || rel.Checksum.Hex != h256('c') {
		t.Errorf("got %+v", rel)
	}
	if rel.Vars["build"] != "20261220" {
		t.Errorf("build = %q, want 20261220", rel.Vars["build"])
	}

	// Exclude sees the JSON encoding of the output object.
	e.Steps[0].Exclude = `"channel":"stable"`
	if rel := mustResolve(t, f, e, Options{Arch: "amd64"}); rel.Version != "3.2" {
		t.Errorf("excluding stable gave %s, want 3.2", rel.Version)
	}
	e.Steps[0].Exclude = `"channel":"beta"`
	if rel := mustResolve(t, f, e, Options{Arch: "amd64"}); rel.Version != "3.10" {
		t.Errorf("excluding beta gave %s, want 3.10", rel.Version)
	}
	e.Steps[0].Exclude = ""
	if rel := mustResolve(t, f, e, Options{Arch: "amd64", Pin: "3.1"}); rel.Version != "3.1" {
		t.Errorf("pin 3.1 gave %s, want 3.1 (not 3.10)", rel.Version)
	}
}

// alpineEntry is modeled on the Alpine entry in catalog/lightweight.yaml.
func alpineEntry() *catalog.Entry {
	return &catalog.Entry{
		ID:   "alpine-virt",
		Arch: map[string]string{"amd64": "x86_64", "arm64": "aarch64"},
		Steps: []catalog.Step{{
			Fetch: "https://dl.example.com/alpine/releases/{arch}/latest-releases.yaml",
			JQ:    `.[] | select(.flavor == "alpine-virt") | {version, file: .iso, sha256}`,
		}},
		URL: "https://dl.example.com/alpine/releases/{arch}/{file}",
	}
}

func TestJQOverYAML(t *testing.T) {
	feed := `---
- branch: v3.22
  version: 3.22.1
  date: 2025-10-01
  flavor: alpine-standard
  iso: alpine-standard-3.22.1-x86_64.iso
  sha256: ` + h256('0') + `
- branch: v3.22
  version: 3.22.1
  date: 2025-10-01
  size: 61865984
  flavor: alpine-virt
  iso: alpine-virt-3.22.1-x86_64.iso
  sha256: ` + h256('d') + `
`
	f := pages("https://dl.example.com/alpine/releases/x86_64/latest-releases.yaml", feed)
	rel := mustResolve(t, f, alpineEntry(), Options{Arch: "amd64"})
	if rel.Version != "3.22.1" || rel.Filename != "alpine-virt-3.22.1-x86_64.iso" || rel.Checksum.String() != "sha256:"+h256('d') {
		t.Errorf("got %+v", rel)
	}
	if want := "https://dl.example.com/alpine/releases/x86_64/alpine-virt-3.22.1-x86_64.iso"; rel.URL != want {
		t.Errorf("URL = %s, want %s", rel.URL, want)
	}
}

func TestJQCandidates(t *testing.T) {
	vars := map[string]string{"arch": "x86_64", "name": "demo"}
	ok := func(doc, program string) []candidate {
		t.Helper()
		got, err := jqCandidates(context.Background(), program, doc, vars)
		if err != nil {
			t.Fatalf("%s: %v", program, err)
		}
		return got
	}

	got := ok(`{"a": 1.5, "b": 2e21, "c": true, "d": "s", "e": 10, "f": 0.1}`, `{a, b, c, d, e, f, arch: $arch, name: $name}`)
	want := map[string]string{"a": "1.5", "b": "2000000000000000000000", "c": "true", "d": "s", "e": "10", "f": "0.1", "arch": "x86_64", "name": "demo"}
	if len(got) != 1 {
		t.Fatalf("got %d candidates", len(got))
	}
	for k, v := range want {
		if got[0].vars[k] != v {
			t.Errorf("var %s = %q, want %q", k, got[0].vars[k], v)
		}
	}
	if !strings.Contains(got[0].text, `"d":"s"`) {
		t.Errorf("candidate text %q is not the JSON object", got[0].text)
	}

	if n := len(ok(`[1, 2, 3]`, `.[] | select(. > 1) | {n: .}`)); n != 2 {
		t.Errorf("got %d candidates, want 2", n)
	}
	// YAML that isn't JSON.
	if c := ok("k: v\nn: 7\n", `{k, n}`); c[0].vars["n"] != "7" || c[0].vars["k"] != "v" {
		t.Errorf("yaml candidate = %v", c[0].vars)
	}

	for name, program := range map[string]string{
		"not an object":    `.[]`,
		"array value":      `{x: [1]}`,
		"object value":     `{x: {y: 1}}`,
		"null value":       `{x: null}`,
		"runtime error":    `error("boom")`,
		"unknown variable": `{x: $nope}`,
		"syntax error":     `{`,
	} {
		if _, err := jqCandidates(context.Background(), program, `[1]`, vars); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

func TestFallback(t *testing.T) {
	// Versions 6..1 are listed; only the pages in `have` exist.
	entry := func(fallback int) (*catalog.Entry, Options) {
		return &catalog.Entry{
			ID:   "fb",
			Arch: map[string]string{"amd64": "amd64"},
			Steps: []catalog.Step{
				{Fetch: site, Match: `v(?P<version>\d+)/`},
				{Fetch: site + "{version}/sum", Match: `(?P<sha256>[0-9a-f]{64})`},
			},
			URL:      site + "{version}/fb.iso",
			Filename: "fb-{version}.iso",
		}, Options{Arch: "amd64", Fallback: fallback}
	}
	fetcher := func(have ...string) *fakeFetcher {
		f := pages(site, "v1/ v2/ v3/ v4/ v5/ v6/")
		for _, v := range have {
			f.pages[site+v+"/sum"] = page{body: h256('1')}
		}
		return f
	}
	sums := func(f *fakeFetcher) int {
		n := 0
		for _, g := range f.gets {
			if strings.HasSuffix(g, "/sum") {
				n++
			}
		}
		return n
	}

	t.Run("next candidate succeeds", func(t *testing.T) {
		f := fetcher("5")
		e, opt := entry(0)
		rel := mustResolve(t, f, e, opt)
		if rel.Version != "5" {
			t.Errorf("version %s, want 5", rel.Version)
		}
		if want := []string{site, site + "6/sum", site + "5/sum"}; strings.Join(f.gets, " ") != strings.Join(want, " ") {
			t.Errorf("gets = %v, want %v", f.gets, want)
		}
	})
	t.Run("default is the best plus three", func(t *testing.T) {
		f := fetcher("2")
		e, opt := entry(0)
		wantError(t, f, e, opt, "404")
		if n := sums(f); n != 4 {
			t.Errorf("tried %d candidates, want 4", n)
		}
		f = fetcher("3")
		if rel := mustResolve(t, f, e, opt); rel.Version != "3" {
			t.Errorf("version %s, want 3", rel.Version)
		}
	})
	t.Run("explicit fallback", func(t *testing.T) {
		f := fetcher("2")
		e, opt := entry(1)
		wantError(t, f, e, opt, "/5/sum")
		if n := sums(f); n != 2 {
			t.Errorf("tried %d candidates, want 2", n)
		}
		f = fetcher("2")
		e, opt = entry(4)
		if rel := mustResolve(t, f, e, opt); rel.Version != "2" {
			t.Errorf("version %s, want 2", rel.Version)
		}
	})
	t.Run("a step without matches falls back too", func(t *testing.T) {
		f := fetcher("5", "4")
		f.pages[site+"6/sum"] = page{body: "nothing here"}
		e, opt := entry(0)
		if rel := mustResolve(t, f, e, opt); rel.Version != "5" {
			t.Errorf("version %s, want 5", rel.Version)
		}
	})
	t.Run("context errors stop at once", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		f := fetcher("5", "4")
		f.onGet = func(u string) error {
			if strings.HasSuffix(u, "/6/sum") {
				cancel()
				return ctx.Err()
			}
			return nil
		}
		e, opt := entry(0)
		_, err := Resolve(ctx, f, e, opt)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("err = %v, want context.Canceled", err)
		}
		if n := sums(f); n != 1 {
			t.Errorf("tried %d candidates after cancel, want 1", n)
		}
	})
	t.Run("a deadline error from a fetcher stops too", func(t *testing.T) {
		f := fetcher("5")
		f.onGet = func(u string) error {
			if strings.HasSuffix(u, "/6/sum") {
				return fmt.Errorf("get %s: %w", u, context.DeadlineExceeded)
			}
			return nil
		}
		e, opt := entry(0)
		if _, err := Resolve(context.Background(), f, e, opt); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("err = %v, want DeadlineExceeded", err)
		}
		if n := sums(f); n != 1 {
			t.Errorf("tried %d candidates, want 1", n)
		}
	})
}

func TestFinishFailureFallsBack(t *testing.T) {
	// The newest version publishes a checksum that isn't valid hex; the next
	// one is fine.
	e := &catalog.Entry{
		ID:   "fb",
		Arch: map[string]string{"amd64": "amd64"},
		Steps: []catalog.Step{
			{Fetch: site, Match: `v(?P<version>\d+)/`},
			{Fetch: site + "{version}/sum", Match: `(?P<sha256>\S+)`},
		},
		URL:      site + "{version}/fb.iso",
		Filename: "fb-{version}.iso",
	}
	f := pages(site, "v1/ v2/", site+"2/sum", "not-a-checksum", site+"1/sum", h256('a'))
	rel := mustResolve(t, f, e, Options{Arch: "amd64"})
	if rel.Version != "1" {
		t.Errorf("version %s, want 1", rel.Version)
	}
}

func TestDocumentOrderWithoutVersion(t *testing.T) {
	e := &catalog.Entry{
		ID:   "order",
		Arch: map[string]string{"amd64": "amd64"},
		Steps: []catalog.Step{
			{Fetch: site, Match: `(?P<dir>d\d)`},
			{Fetch: site + "{dir}", Match: `(?P<version>\d+) (?P<sha256>[0-9a-f]{64})`},
		},
		URL:      site + "{dir}/x.iso",
		Filename: "x-{version}.iso",
	}
	f := pages(site, "d2 d9 d1", site+"d2", "5 "+h256('2'), site+"d9", "9 "+h256('9'), site+"d1", "1 "+h256('1'))
	if rel := mustResolve(t, f, e, Options{Arch: "amd64"}); rel.Vars["dir"] != "d2" {
		t.Errorf("dir = %s, want d2 (first in the document)", rel.Vars["dir"])
	}
}

func TestFrom(t *testing.T) {
	step := func(from, match string) *catalog.Entry {
		return &catalog.Entry{
			ID:       "from",
			Arch:     map[string]string{"amd64": "amd64"},
			Steps:    []catalog.Step{{Fetch: site + "latest", From: from, Match: match}},
			URL:      site + "dl/{version}",
			Filename: "from-{version}.iso",
			Checksum: &catalog.Sidecar{Fetch: site + "sum-{version}"},
		}
	}
	withHeader := func(h http.Header, final string, extra ...string) *fakeFetcher {
		f := pages(extra...)
		f.pages[site+"latest"] = page{header: h, final: final, body: "BODY version=0.0"}
		return f
	}
	tests := []struct {
		name    string
		entry   *catalog.Entry
		fetcher *fakeFetcher
		want    string
		wantErr string
	}{
		{
			"final-url",
			step("final-url", `/releases/(?P<version>[\d.]+)/`),
			withHeader(nil, site+"releases/4.5.6/file.iso", site+"sum-4.5.6", h256('a')),
			"4.5.6", "",
		},
		{
			"header",
			step("header:X-Version", `^(?P<version>[\d.]+)$`),
			withHeader(http.Header{"X-Version": {"7.8"}}, "", site+"sum-7.8", h256('a')),
			"7.8", "",
		},
		{
			"last-modified",
			step("last-modified", `(?P<version>\d{8}T\d{6}Z)`),
			withHeader(http.Header{"Last-Modified": {"Sat, 18 Oct 2025 12:00:00 GMT"}}, "", site+"sum-20251018T120000Z", h256('a')),
			"20251018T120000Z", "",
		},
		{
			"missing header",
			step("header:X-Version", `(?P<version>.+)`),
			withHeader(nil, ""),
			"", "no X-Version header",
		},
		{
			"bad last-modified",
			step("last-modified", `(?P<version>.+)`),
			withHeader(http.Header{"Last-Modified": {"yesterday"}}, ""),
			"", "Last-Modified",
		},
		{
			"unknown from",
			step("cookie", `(?P<version>.+)`),
			withHeader(nil, ""),
			"", `unknown from "cookie"`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.wantErr != "" {
				wantError(t, tc.fetcher, tc.entry, Options{Arch: "amd64"}, tc.wantErr)
				return
			}
			rel := mustResolve(t, tc.fetcher, tc.entry, Options{Arch: "amd64"})
			if rel.Version != tc.want {
				t.Errorf("version %s, want %s", rel.Version, tc.want)
			}
			if len(tc.fetcher.heads) != 1 || tc.fetcher.heads[0] != site+"latest" {
				t.Errorf("heads = %v, want one HEAD of the step URL", tc.fetcher.heads)
			}
			for _, g := range tc.fetcher.gets {
				if g == site+"latest" {
					t.Errorf("GET of the step URL; From %q must use HEAD", tc.entry.Steps[0].From)
				}
			}
		})
	}
}

func TestFilenameTemplate(t *testing.T) {
	e := &catalog.Entry{
		ID:       "tmpl",
		Arch:     map[string]string{"amd64": "x86_64"},
		Steps:    []catalog.Step{{Fetch: site + "v", Match: `(?P<version>[\d.]+) (?P<sha256>[0-9a-f]{64})`}},
		URL:      site + "download/latest",
		Filename: "demo-{version}-{arch}.iso",
	}
	f := pages(site+"v", "2.5 "+h256('a'))
	rel := mustResolve(t, f, e, Options{Arch: "amd64"})
	if rel.Filename != "demo-2.5-x86_64.iso" || rel.URL != site+"download/latest" {
		t.Errorf("got %s from %s", rel.Filename, rel.URL)
	}
	// Without the template the URL's last segment is used, and it has no version.
	e.Filename = ""
	wantError(t, f, e, Options{Arch: "amd64"}, "not a plain .iso name")
}

func TestFilenameRules(t *testing.T) {
	tests := []struct {
		name     string
		url      string
		filename string
		file     string
		want     string // substring of the error; "" means success with this file name
	}{
		{"plain", site + "{file}", "", "demo-1.0.iso", ""},
		{"path in url", site + "a/b/{file}?x=1", "", "demo-1.0.iso", ""},
		{"escaped name", site + "demo%2D1.0.iso", "", "x", ""},
		{"dot dot template", site + "x", "{file}", "../evil-1.0.iso", "not a plain .iso name"},
		{"slash template", site + "x", "{file}", "a/demo-1.0.iso", "not a plain .iso name"},
		{"hidden", site + "x", "{file}", ".hidden-1.0.iso", "not a plain .iso name"},
		{"wrong extension", site + "{file}", "", "x-1.0.img", "not a plain .iso name"},
		{"no extension", site + "x", "{file}", "demo-1.0", "not a plain .iso name"},
		{"escaped traversal", site + "%2e%2e%2fevil-1.0.iso", "", "x", "not a plain .iso name"},
		{"escaped slash", site + "a%2Fdemo-1.0.iso", "", "x", "not a plain .iso name"},
		{"bad escape", site + "demo-1.0%zz.iso", "", "x", "invalid URL escape"},
		{"empty path", site, "", "x", "not a plain .iso name"},
		{"no version in name", site + "{file}", "", "demo.iso", `doesn't contain version "1.0"`},
		{"http", "http://releases.example.com/{file}", "", "demo-1.0.iso", "not an https URL"},
		{"no host", "https:///{file}", "", "demo-1.0.iso", "not an https URL"},
		{"scheme-less", "releases.example.com/{file}", "", "demo-1.0.iso", "not an https URL"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := &catalog.Entry{
				ID:       "names",
				Arch:     map[string]string{"amd64": "amd64"},
				Steps:    []catalog.Step{{Fetch: site + "v", Match: `(?P<version>[\d.]+) (?P<file>\S+) (?P<sha256>[0-9a-f]{64})`}},
				URL:      tc.url,
				Filename: tc.filename,
			}
			f := pages(site+"v", "1.0 "+tc.file+" "+h256('a'))
			if tc.want != "" {
				wantError(t, f, e, Options{Arch: "amd64"}, tc.want)
				return
			}
			rel := mustResolve(t, f, e, Options{Arch: "amd64"})
			if want := "demo-1.0.iso"; rel.Filename != want {
				t.Errorf("file name %q, want %q", rel.Filename, want)
			}
		})
	}
}

func TestMissingVersion(t *testing.T) {
	e := &catalog.Entry{
		ID:    "nover",
		Arch:  map[string]string{"amd64": "amd64"},
		Steps: []catalog.Step{{Fetch: site + "v", Match: `(?P<sha256>[0-9a-f]{64})`}},
		URL:   site + "demo.iso",
	}
	wantError(t, pages(site+"v", h256('a')), e, Options{Arch: "amd64"}, "no version")
}

func TestChecksumSources(t *testing.T) {
	const doc = "# checksums\n%s  other.iso\n%s  demo-1.0.iso\n"
	entry := func(sc *catalog.Sidecar) *catalog.Entry {
		return &catalog.Entry{
			ID:       "sums",
			Arch:     map[string]string{"amd64": "amd64"},
			Steps:    []catalog.Step{{Fetch: site + "v", Match: `(?P<version>[\d.]+)`}},
			URL:      site + "demo-{version}.iso",
			Checksum: sc,
		}
	}
	gnu := fmt.Sprintf(doc, h256('1'), h256('2'))
	tests := []struct {
		name    string
		sidecar *catalog.Sidecar
		body    string
		want    string
		wantErr string
	}{
		{"gnu line for the file", &catalog.Sidecar{Fetch: "{url}.sums"}, gnu, "sha256:" + h256('2'), ""},
		{"gnu with sha512", &catalog.Sidecar{Fetch: "{url}.sums"}, h512('c') + "  demo-1.0.iso\n", "sha512:" + h512('c'), ""},
		{"gnu uppercase is lowercased", &catalog.Sidecar{Fetch: "{url}.sums"}, strings.ToUpper(h256('a')) + " *demo-1.0.iso\n", "sha256:" + h256('a'), ""},
		{"bsd line", &catalog.Sidecar{Fetch: "{url}.sums"}, "SHA256 (demo-1.0.iso) = " + h256('b') + "\n", "sha256:" + h256('b'), ""},
		{"bare hash", &catalog.Sidecar{Fetch: "{url}.sha256"}, h256('3') + "\n", "sha256:" + h256('3'), ""},
		{"only line wins over a different name", &catalog.Sidecar{Fetch: "{url}.sums"}, h256('4') + "  renamed.iso\n", "sha256:" + h256('4'), ""},
		{"two lines, none for the file", &catalog.Sidecar{Fetch: "{url}.sums"}, fmt.Sprintf("%s  a.iso\n%s  b.iso\n", h256('1'), h256('2')), "", `no checksum for "demo-1.0.iso"`},
		{"no checksum at all", &catalog.Sidecar{Fetch: "{url}.sums"}, "nothing\n", "", "no checksum"},
		{"match sha256", &catalog.Sidecar{Fetch: "{url}.sums", Match: `(?P<sha256>[0-9a-f]{64})\s+{filename}`}, gnu, "sha256:" + h256('2'), ""},
		{"match sha512", &catalog.Sidecar{Fetch: "{url}.sums", Match: `(?P<sha512>[0-9a-f]{128})\s+{filename}`}, h512('9') + " demo-1.0.iso", "sha512:" + h512('9'), ""},
		{"match quotes the filename", &catalog.Sidecar{Fetch: "{url}.sums", Match: `(?P<sha256>[0-9a-f]{64}) {filename}`}, h256('5') + " demo-1x0.iso\n" + h256('6') + " demo-1.0.iso\n", "sha256:" + h256('6'), ""},
		{"match uses vars", &catalog.Sidecar{Fetch: "{url}.sums", Match: `{version}: (?P<sha256>[0-9a-f]{64})`}, "1.0: " + h256('7'), "sha256:" + h256('7'), ""},
		{"match finds nothing", &catalog.Sidecar{Fetch: "{url}.sums", Match: `(?P<sha256>[0-9a-f]{64}) nope`}, gnu, "", "found nothing"},
		{"match without a hash group", &catalog.Sidecar{Fetch: "{url}.sums", Match: `demo`}, gnu, "", "no sha256 or sha512 group"},
		{"invalid hash", &catalog.Sidecar{Fetch: "{url}.sums", Match: `(?P<sha256>\S+) {filename}`}, "xyz demo-1.0.iso", "", "invalid sha256 checksum"},
		{"unknown placeholder", &catalog.Sidecar{Fetch: "{nope}.sums"}, gnu, "", "no value for {nope}"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := pages(site+"v", "1.0", site+"demo-1.0.iso.sums", tc.body, site+"demo-1.0.iso.sha256", tc.body)
			e := entry(tc.sidecar)
			if tc.wantErr != "" {
				wantError(t, f, e, Options{Arch: "amd64"}, tc.wantErr)
				return
			}
			if rel := mustResolve(t, f, e, Options{Arch: "amd64"}); rel.Checksum.String() != tc.want {
				t.Errorf("checksum %v, want %s", rel.Checksum, tc.want)
			}
		})
	}
}

func TestChecksumVariablePrecedence(t *testing.T) {
	e := func(match string, sc *catalog.Sidecar) *catalog.Entry {
		return &catalog.Entry{
			ID:       "prec",
			Arch:     map[string]string{"amd64": "amd64"},
			Steps:    []catalog.Step{{Fetch: site + "v", Match: match}},
			URL:      site + "demo-{version}.iso",
			Checksum: sc,
		}
	}
	both := `(?P<version>[\d.]+) (?P<sha256>[0-9a-f]{64}) (?P<sha512>[0-9a-f]{128})`
	f := pages(site+"v", "1.0 "+h256('a')+" "+h512('b'), site+"side", h256('c'))
	if rel := mustResolve(t, f, e(both, nil), Options{Arch: "amd64"}); rel.Checksum.Algo != "sha512" || rel.Checksum.Hex != h512('b') {
		t.Errorf("both variables: %v, want the sha512", rel.Checksum)
	}
	// A variable beats the sidecar, which is never fetched.
	f = pages(site+"v", "1.0 "+h256('a')+" "+h512('b'))
	rel := mustResolve(t, f, e(both, &catalog.Sidecar{Fetch: site + "side"}), Options{Arch: "amd64"})
	if rel.Checksum.Hex != h512('b') || len(f.gets) != 1 {
		t.Errorf("sidecar was used: %v, gets %v", rel.Checksum, f.gets)
	}
	// Neither a variable nor a sidecar.
	f = pages(site+"v", "1.0")
	wantError(t, f, e(`(?P<version>[\d.]+)`, nil), Options{Arch: "amd64"}, "no checksum")
	// A bad variable isn't rescued by the sidecar.
	f = pages(site+"v", "1.0 "+h256('a')[:63], site+"side", h256('c'))
	wantError(t, f, e(`(?P<version>[\d.]+) (?P<sha256>[0-9a-f]+)`, &catalog.Sidecar{Fetch: site + "side"}), Options{Arch: "amd64"}, "invalid sha256")
}

func signedUbuntu(sigURL string) *catalog.Entry {
	e := ubuntuEntry()
	e.Signature = &catalog.Signature{Type: catalog.SigDetachedChecksums, URL: sigURL}
	e.Keys = []string{"k"}
	return e
}

func TestDetachedChecksums(t *testing.T) {
	// Odd bytes at the edges prove the signature is checked over the raw
	// document, not over what the match saw.
	raw := "  \r\n" + ubuntuSums("26.04.1", h256('6')) + "# trailer\t\n\n"
	f := func(sig string) *fakeFetcher {
		f := ubuntuFetcher()
		f.pages[site+"26.04.1/SHA256SUMS"] = page{body: raw}
		f.pages[site+"26.04.1/SHA256SUMS.gpg"] = page{body: sig}
		return f
	}
	sigURL := site + "{version}/SHA256SUMS.gpg"

	rel := mustResolve(t, f(goodSig(raw)), signedUbuntu(sigURL), Options{Arch: "amd64", Pin: "26", Verifier: fakeVerifier{}})
	if rel.SignedBy != "DETACHED-FPR" || rel.Checksum.Hex != h256('6') {
		t.Errorf("got SignedBy %q, checksum %v", rel.SignedBy, rel.Checksum)
	}

	// {filename} and {url} are available in the signature URL.
	e := signedUbuntu(site + "{version}/{filename}.gpg")
	ff := f(goodSig(raw))
	ff.pages[site+"26.04.1/ubuntu-26.04.1-live-server-amd64.iso.gpg"] = page{body: goodSig(raw)}
	if rel := mustResolve(t, ff, e, Options{Arch: "amd64", Pin: "26", Verifier: fakeVerifier{}}); rel.SignedBy != "DETACHED-FPR" {
		t.Errorf("SignedBy %q", rel.SignedBy)
	}
	e = signedUbuntu("{url}.gpg")
	ff.pages[site+"26.04.1/ubuntu-26.04.1-live-server-amd64.iso.gpg"] = page{body: goodSig(raw)}
	if rel := mustResolve(t, ff, e, Options{Arch: "amd64", Pin: "26", Verifier: fakeVerifier{}}); rel.SignedBy != "DETACHED-FPR" {
		t.Errorf("SignedBy %q", rel.SignedBy)
	}

	// A signature over the matched line instead of the raw bytes fails.
	wantError(t, f(goodSig(ubuntuSums("26.04.1", h256('6')))), signedUbuntu(sigURL), Options{Arch: "amd64", Pin: "26", Verifier: fakeVerifier{}}, "bad detached signature")
	wantError(t, f("GOOD:"+h256('0')), signedUbuntu(sigURL), Options{Arch: "amd64", Pin: "26", Verifier: fakeVerifier{}}, "SHA256SUMS.gpg")
	// A missing signature file fails the update.
	ff = f("")
	delete(ff.pages, site+"26.04.1/SHA256SUMS.gpg")
	wantError(t, ff, signedUbuntu(sigURL), Options{Arch: "amd64", Pin: "26", Verifier: fakeVerifier{}}, "404")
	// No verifier is an error, not a panic.
	wantError(t, f(goodSig(raw)), signedUbuntu(sigURL), Options{Arch: "amd64", Pin: "26"}, "needs a verifier")
	// An unknown placeholder in the signature URL.
	wantError(t, f(goodSig(raw)), signedUbuntu(site+"{nope}"), Options{Arch: "amd64", Pin: "26", Verifier: fakeVerifier{}}, "{nope}")
}

func TestDetachedChecksumsOverSidecar(t *testing.T) {
	e := &catalog.Entry{
		ID:        "side",
		Arch:      map[string]string{"amd64": "amd64"},
		Steps:     []catalog.Step{{Fetch: site + "v", Match: `(?P<version>[\d.]+)`}},
		URL:       site + "demo-{version}.iso",
		Checksum:  &catalog.Sidecar{Fetch: site + "SUMS"},
		Signature: &catalog.Signature{Type: catalog.SigDetachedChecksums, URL: site + "SUMS.sig"},
	}
	sums := h256('a') + "  demo-1.0.iso\n\n"
	f := pages(site+"v", "1.0", site+"SUMS", sums, site+"SUMS.sig", goodSig(sums))
	rel := mustResolve(t, f, e, Options{Arch: "amd64", Verifier: fakeVerifier{}})
	if rel.SignedBy != "DETACHED-FPR" {
		t.Errorf("SignedBy %q", rel.SignedBy)
	}
	f.pages[site+"SUMS.sig"] = page{body: goodSig("other")}
	wantError(t, f, e, Options{Arch: "amd64", Verifier: fakeVerifier{}}, "bad detached signature")
}

func TestDetachedISO(t *testing.T) {
	e := ubuntuEntry()
	e.Signature = &catalog.Signature{Type: catalog.SigDetachedISO, URL: "{url}.sig"}
	f := ubuntuFetcher()
	rel := mustResolve(t, f, e, Options{Arch: "amd64"}) // no verifier needed
	if want := site + "26.04.1/ubuntu-26.04.1-live-server-amd64.iso.sig"; rel.ISOSignatureURL != want {
		t.Errorf("ISOSignatureURL = %q, want %q", rel.ISOSignatureURL, want)
	}
	if rel.SignedBy != "" {
		t.Errorf("SignedBy = %q for an unsigned checksum document", rel.SignedBy)
	}
	for _, g := range f.gets {
		if strings.HasSuffix(g, ".sig") {
			t.Errorf("fetched %s; the ISO signature is the caller's to check", g)
		}
	}
	e.Signature.Type = "magic"
	wantError(t, ubuntuFetcher(), e, Options{Arch: "amd64"}, `unknown signature type "magic"`)
}

func clearsigned(signed, appended string) string {
	return "preamble\n" + beginMark + "\n" + signed + endMark + "\n" + appended
}

func clearsignedEntry() *catalog.Entry {
	return &catalog.Entry{
		ID:   "clear",
		Arch: map[string]string{"amd64": "amd64"},
		Steps: []catalog.Step{{
			Fetch:       site + "SUMS.asc",
			Clearsigned: true,
			Match:       `(?m)^(?P<sha256>[0-9a-f]{64})  (?P<file>demo-(?P<version>[\d.]+)\.iso)$`,
		}},
		URL: site + "{file}",
	}
}

func TestClearsigned(t *testing.T) {
	opt := Options{Arch: "amd64", Verifier: fakeVerifier{}}
	signed := h256('a') + "  demo-1.0.iso\n"
	forged := h256('f') + "  demo-2.0.iso\n" + h256('e') + "  demo-1.0.iso\n"

	t.Run("signed text only", func(t *testing.T) {
		f := pages(site+"SUMS.asc", clearsigned(signed, forged))
		rel := mustResolve(t, f, clearsignedEntry(), opt)
		if rel.Version != "1.0" || rel.Checksum.Hex != h256('a') || rel.SignedBy != "CLEAR-FPR" {
			t.Errorf("got version %s checksum %v signed by %q", rel.Version, rel.Checksum, rel.SignedBy)
		}
	})
	t.Run("nothing but unsigned lines", func(t *testing.T) {
		f := pages(site+"SUMS.asc", clearsigned("nothing\n", forged))
		wantError(t, f, clearsignedEntry(), opt, "no candidates")
	})
	t.Run("verification fails", func(t *testing.T) {
		f := pages(site+"SUMS.asc", signed)
		wantError(t, f, clearsignedEntry(), opt, "no signature")
		f = pages(site+"SUMS.asc", beginMark+"\n"+signed)
		wantError(t, f, clearsignedEntry(), opt, "unterminated")
	})
	t.Run("no verifier", func(t *testing.T) {
		f := pages(site+"SUMS.asc", clearsigned(signed, ""))
		wantError(t, f, clearsignedEntry(), Options{Arch: "amd64"}, "no verifier")
	})
	t.Run("needs a body", func(t *testing.T) {
		e := clearsignedEntry()
		e.Steps[0].From = "final-url"
		wantError(t, pages(site+"SUMS.asc", ""), e, opt, "clearsigned needs from body")
	})
	t.Run("plaintext feeds a later step", func(t *testing.T) {
		e := &catalog.Entry{
			ID:   "clear2",
			Arch: map[string]string{"amd64": "amd64"},
			Steps: []catalog.Step{
				{Fetch: site + "index.asc", Clearsigned: true, Match: `(?m)^latest=(?P<version>[\d.]+)$`},
				{Fetch: site + "{version}/SUMS", Match: `(?P<sha256>[0-9a-f]{64})`},
			},
			URL:      site + "{version}/demo.iso",
			Filename: "demo-{version}.iso",
		}
		f := pages(site+"index.asc", clearsigned("latest=1.0\n", "latest=9.9\n"), site+"1.0/SUMS", h256('a'), site+"9.9/SUMS", h256('b'))
		rel := mustResolve(t, f, e, opt)
		// The signed index doesn't sign the checksum document.
		if rel.Version != "1.0" || rel.SignedBy != "" {
			t.Errorf("got version %s, SignedBy %q", rel.Version, rel.SignedBy)
		}
	})
	t.Run("detached signature over the clearsigned document", func(t *testing.T) {
		e := clearsignedEntry()
		e.Signature = &catalog.Signature{Type: catalog.SigDetachedChecksums, URL: site + "SUMS.asc.sig"}
		raw := clearsigned(signed, forged)
		f := pages(site+"SUMS.asc", raw, site+"SUMS.asc.sig", goodSig(raw))
		rel := mustResolve(t, f, e, opt)
		if rel.SignedBy != "DETACHED-FPR" {
			t.Errorf("SignedBy %q", rel.SignedBy)
		}
		f.pages[site+"SUMS.asc.sig"] = page{body: goodSig(signed)} // the signed text alone isn't the raw document
		wantError(t, f, e, opt, "bad detached signature")
	})
}

func TestNoCandidatesNamesTheStep(t *testing.T) {
	f := pages(site, "nothing to see")
	err := func() error {
		_, err := Resolve(context.Background(), f, ubuntuEntry(), Options{Arch: "amd64"})
		return err
	}()
	if err == nil || !strings.Contains(err.Error(), "ubuntu: step 1: no candidates") {
		t.Errorf("err = %v", err)
	}
	f = pages(site, `href="24.04.3/"`, site+"24.04.3/SHA256SUMS", "empty")
	if _, err := Resolve(context.Background(), f, ubuntuEntry(), Options{Arch: "amd64"}); err == nil || !strings.Contains(err.Error(), "step 2: no candidates") {
		t.Errorf("err = %v", err)
	}
}

func TestFetchErrorsKeepContext(t *testing.T) {
	_, err := Resolve(context.Background(), pages(), ubuntuEntry(), Options{Arch: "amd64"})
	if err == nil || !strings.Contains(err.Error(), "ubuntu") || !strings.Contains(err.Error(), site) {
		t.Errorf("err = %v, want entry ID and URL", err)
	}
}

func TestCompareVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int
	}{
		// the doc comment's examples
		{"9.10", "9.9", 1},
		{"2026.3a", "2026.3", 1},
		{"20261115T170104Z", "20261108T000000Z", 1},
		// the rest
		{"1.0", "1.0", 0},
		{"", "", 0},
		{"", "1", -1},
		{"1.2.3", "1.2", 1},
		{"1.2", "1.2.0", -1},
		{"1.02", "1.2", 0},
		{"007", "7", 0},
		{"0", "00", 0},
		{"1.10", "1.9", 1},
		{"1.9.9", "1.10", -1},
		{"24.04.1", "24.04", 1},
		{"24.04.1", "24.10", -1},
		{"12345678901234567890", "12345678901234567891", -1}, // beyond int64
		{"1-2", "1.2", 0}, // separators only separate
		{"1_2~3", "1.2.3", 0},
		{"v1.2", "v1.10", -1},
		{"rc1", "rc2", -1},
		{"1.0rc1", "1.0rc2", -1},
		{"1.0a", "1.0b", -1},
		{"1.0b", "1.0a", 1},
		{"beta", "alpha", 1},
		{"Zeta", "alpha", -1}, // text compares bytewise
		{"1.0rc1", "1.0", 1},  // the longer version is newer
		{"1.0.1", "1.0rc1", 1},
		{"20251018T120000Z", "20251018T120000Z", 0},
		{"20251018T120000Z", "20251018T120001Z", -1},
		{"20251018T120000Z", "9", 1},
	}
	for _, tc := range tests {
		if got := CompareVersions(tc.a, tc.b); got != tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
		if got := CompareVersions(tc.b, tc.a); got != -tc.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", tc.b, tc.a, got, -tc.want)
		}
	}
}

func TestMatchesPin(t *testing.T) {
	tests := []struct {
		version, pin string
		want         bool
	}{
		// the doc comment's examples
		{"24.04", "24.04", true},
		{"24.04.3", "24.04", true},
		{"24.040", "24.04", false},
		{"9.6", "9", true},
		{"9-1", "9", true},
		{"90", "9", false},
		// the rest
		{"anything", "", true},
		{"", "", true},
		{"24.04", "24.04.3", false},
		{"25.04", "24.04", false},
		{"24.04rc1", "24.04", false},
		{"24.04-rc1", "24.04", true},
		{"24.04_1", "24.04", true},
		{"24.04 beta", "24.04", true},
		{"9a", "9", false},
		{"v9.1", "9", false},
		{"20251018T120000Z", "20251018", false},
		{"20251018T120000Z", "20251018T120000Z", true},
		{"9é", "9", false},
		{"9.é", "9", true},
		{"", "9", false},
	}
	for _, tc := range tests {
		if got := MatchesPin(tc.version, tc.pin); got != tc.want {
			t.Errorf("MatchesPin(%q, %q) = %v, want %v", tc.version, tc.pin, got, tc.want)
		}
	}
}
