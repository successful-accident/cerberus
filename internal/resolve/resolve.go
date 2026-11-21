// Package resolve runs a catalog entry's steps against live feeds and
// returns the newest release: its version, download URL, file name,
// checksum, and signature details.
package resolve

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/itchyny/gojq"
	"go.yaml.in/yaml/v3"

	"github.com/successful-accident/cerberus/internal/catalog"
	"github.com/successful-accident/cerberus/internal/download"
	"github.com/successful-accident/cerberus/internal/verify"
)

// Fetcher fetches documents over HTTPS. *download.Client satisfies it.
type Fetcher interface {
	Get(ctx context.Context, url string) (*download.Doc, error)
	Head(ctx context.Context, url string) (*download.Doc, error)
}

// Verifier checks OpenPGP signatures against an entry's pinned keys.
// *verify.Keyring satisfies it.
type Verifier interface {
	VerifyDetached(data, sig []byte) (fingerprint string, err error)
	VerifyClearsigned(doc []byte) (plaintext []byte, fingerprint string, err error)
}

// Options tune one resolution.
type Options struct {
	// Arch is amd64 or arm64, and must be a key of the entry's Arch map.
	Arch string
	// Pin is an optional version prefix; see MatchesPin.
	Pin string
	// Verifier is required when the entry has a clearsigned step or a
	// detached-checksums signature.
	Verifier Verifier
	// Fallback is how many more candidates a step tries after its best one
	// fails in a later step. Zero means 3.
	Fallback int
}

// Release is a resolved ISO that hasn't been downloaded yet.
type Release struct {
	EntryID  string
	Version  string
	URL      string
	Filename string
	Checksum verify.Checksum
	// SignedBy is the fingerprint that signed the document the checksum came
	// from, or "" when that document is unsigned.
	SignedBy string
	// ISOSignatureURL is set for detached-iso entries. The caller checks the
	// downloaded file against it.
	ISOSignatureURL string
	// Vars holds every variable at the end of resolution, for debugging.
	Vars map[string]string
}

// ErrSignature wraps every failed signature check. Resolve never falls back
// to another candidate after one: a bad signature on a published release is
// a security event, not a missing file, so it must surface instead of
// quietly giving way to an older release.
var ErrSignature = errors.New("signature check failed")

// Resolve runs e's steps and returns the newest release.
//
// It starts with the variable arch set to e.Arch[opt.Arch], and fails if
// that key is missing. Then, for each step in order:
//  1. Render Fetch with catalog.Render, without quoting. Fetch it with Get
//     when From is body or empty; otherwise use Head.
//  2. Take the step's text from From. With Clearsigned, verify the body
//     with opt.Verifier and use only the returned plaintext.
//  3. Extract candidates. For Match, replace placeholders with
//     regexp.QuoteMeta'd values, compile, and make one candidate per match.
//     For JQ, parse the body as JSON (YAML when that fails), pass every
//     variable as $name, and make one candidate per output object; numbers
//     are formatted without exponents.
//  4. Drop candidates whose text matches Exclude, and, when opt.Pin is set,
//     candidates whose version fails MatchesPin. Drop exact duplicates.
//  5. Sort candidates newest first with CompareVersions when they carry a
//     version, else keep document order. No candidates is an error that
//     names the step.
//  6. Try the candidates in order, each merged over the current variables,
//     running the remaining steps and the finish below. If that fails with
//     an error other than the context's or ErrSignature, try the next one,
//     up to 1 + opt.Fallback candidates. Return the last error if all fail.
//
// To finish, Resolve renders e.URL, which must be an https:// URL. The file
// name is e.Filename rendered, or the URL path's last segment, unescaped. It
// must pass catalog.ValidFilename and contain the version variable, which
// must exist. The checksum is the sha512 variable, else sha256, else the
// e.Checksum sidecar, with url and filename added as variables. It must be
// valid hex of the right length, and is stored lowercase. For a
// detached-checksums signature, Resolve fetches the rendered Signature.URL
// and verifies it over the raw bytes of the document that produced the
// checksum. When that document was clearsigned, its signer counts too. For
// detached-iso, it only renders ISOSignatureURL.
func Resolve(ctx context.Context, f Fetcher, e *catalog.Entry, opt Options) (*Release, error) {
	arch, ok := e.Arch[opt.Arch]
	if !ok {
		return nil, fmt.Errorf("%s: no architecture %q", e.ID, opt.Arch)
	}
	r := &run{f: f, e: e, opt: opt, tries: 1 + opt.Fallback}
	if opt.Fallback <= 0 {
		r.tries = 4
	}
	return r.step(ctx, 0, trail{vars: map[string]string{"arch": arch}})
}

// run holds what stays fixed during one Resolve.
type run struct {
	f     Fetcher
	e     *catalog.Entry
	opt   Options
	tries int // candidates to try per step
}

// source is a document that produced a variable, as fetched.
type source struct {
	raw    []byte
	signer string // clearsign fingerprint, or ""
}

// trail is the state along one path through the candidates: the variables so
// far, and the document behind each checksum variable.
type trail struct {
	vars map[string]string
	docs map[string]source // keyed by "sha256" or "sha512"
}

// candidate is one extraction result.
type candidate struct {
	vars map[string]string
	text string
}

func (t trail) with(c candidate, src source) trail {
	out := trail{vars: make(map[string]string, len(t.vars)+len(c.vars)), docs: map[string]source{}}
	for k, v := range t.vars {
		out.vars[k] = v
	}
	for k, v := range t.docs {
		out.docs[k] = v
	}
	for k, v := range c.vars {
		out.vars[k] = v
		if k == "sha256" || k == "sha512" {
			out.docs[k] = src
		}
	}
	return out
}

func isContextErr(ctx context.Context, err error) bool {
	return ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

func (r *run) step(ctx context.Context, i int, t trail) (*Release, error) {
	if i == len(r.e.Steps) {
		return r.finish(ctx, t)
	}
	cands, src, err := r.candidates(ctx, i, t.vars)
	if err != nil {
		return nil, fmt.Errorf("%s: step %d: %w", r.e.ID, i+1, err)
	}
	var lastErr error
	for _, c := range cands[:min(len(cands), r.tries)] {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		rel, err := r.step(ctx, i+1, t.with(c, src))
		if err == nil {
			return rel, nil
		}
		if isContextErr(ctx, err) || errors.Is(err, ErrSignature) {
			return nil, err
		}
		lastErr = err
	}
	return nil, lastErr
}

// candidates fetches step i's document and returns its filtered, ordered
// candidates and the document they came from.
func (r *run) candidates(ctx context.Context, i int, vars map[string]string) ([]candidate, source, error) {
	st := r.e.Steps[i]
	text, src, err := r.fetchText(ctx, st, vars)
	if err != nil {
		return nil, source{}, err
	}
	var cands []candidate
	if st.JQ != "" {
		cands, err = jqCandidates(ctx, st.JQ, text, vars)
	} else {
		cands, err = matchCandidates(st.Match, text, vars)
	}
	if err != nil {
		return nil, source{}, err
	}

	var exclude *regexp.Regexp
	if st.Exclude != "" {
		if exclude, err = compileTemplate(st.Exclude, vars); err != nil {
			return nil, source{}, fmt.Errorf("exclude: %w", err)
		}
	}
	seen := map[string]bool{}
	kept := cands[:0]
	for _, c := range cands {
		if exclude != nil && exclude.MatchString(c.text) {
			continue
		}
		if v, ok := c.vars["version"]; ok && !MatchesPin(v, r.opt.Pin) {
			continue
		}
		key := fmt.Sprintf("%s\x00%v", c.text, c.vars)
		if seen[key] {
			continue
		}
		seen[key] = true
		kept = append(kept, c)
	}
	if len(kept) == 0 {
		return nil, source{}, fmt.Errorf("no candidates from %s", st.Fetch)
	}
	// Versioned candidates come first, newest first; the rest keep their
	// document order.
	sort.SliceStable(kept, func(a, b int) bool {
		va, oka := kept[a].vars["version"]
		vb, okb := kept[b].vars["version"]
		if oka != okb {
			return oka
		}
		return oka && CompareVersions(va, vb) > 0
	})
	return kept, src, nil
}

// fetchText fetches a step's document and returns the text the step reads.
func (r *run) fetchText(ctx context.Context, st catalog.Step, vars map[string]string) (string, source, error) {
	u, err := catalog.Render(st.Fetch, vars, nil)
	if err != nil {
		return "", source{}, err
	}
	from := st.From
	if from == "" {
		from = catalog.FromBody
	}
	if st.Clearsigned && from != catalog.FromBody {
		return "", source{}, fmt.Errorf("clearsigned needs from body, not %q", st.From)
	}
	if from == catalog.FromBody {
		doc, err := r.f.Get(ctx, u)
		if err != nil {
			return "", source{}, fmt.Errorf("get %s: %w", u, err)
		}
		src := source{raw: doc.Body}
		if !st.Clearsigned {
			return string(doc.Body), src, nil
		}
		if r.opt.Verifier == nil {
			return "", source{}, fmt.Errorf("clearsigned %s: no verifier", u)
		}
		plain, fpr, err := r.opt.Verifier.VerifyClearsigned(doc.Body)
		if err != nil {
			return "", source{}, fmt.Errorf("verify %s: %w: %w", u, ErrSignature, err)
		}
		src.signer = fpr
		return string(plain), src, nil
	}

	doc, err := r.f.Head(ctx, u)
	if err != nil {
		return "", source{}, fmt.Errorf("head %s: %w", u, err)
	}
	var text string
	switch {
	case from == catalog.FromFinalURL:
		text = doc.FinalURL
	case from == catalog.FromLastModified:
		h := doc.Header.Get("Last-Modified")
		t, err := http.ParseTime(h)
		if err != nil {
			return "", source{}, fmt.Errorf("head %s: Last-Modified %q: %w", u, h, err)
		}
		text = t.UTC().Format("20060102T150405Z")
	case strings.HasPrefix(from, catalog.FromHeaderPrefix):
		name := strings.TrimPrefix(from, catalog.FromHeaderPrefix)
		if text = doc.Header.Get(name); text == "" {
			return "", source{}, fmt.Errorf("head %s: no %s header", u, name)
		}
	default:
		return "", source{}, fmt.Errorf("unknown from %q", st.From)
	}
	return text, source{raw: []byte(text)}, nil
}

// compileTemplate renders regex's placeholders with quoted values and
// compiles it.
func compileTemplate(regex string, vars map[string]string) (*regexp.Regexp, error) {
	s, err := catalog.Render(regex, vars, regexp.QuoteMeta)
	if err != nil {
		return nil, err
	}
	return regexp.Compile(s)
}

func matchCandidates(match, text string, vars map[string]string) ([]candidate, error) {
	re, err := compileTemplate(match, vars)
	if err != nil {
		return nil, fmt.Errorf("match: %w", err)
	}
	names := re.SubexpNames()
	var out []candidate
	for _, m := range re.FindAllStringSubmatch(text, -1) {
		c := candidate{vars: map[string]string{}, text: m[0]}
		for i, name := range names {
			if name != "" && m[i] != "" {
				c.vars[name] = m[i]
			}
		}
		out = append(out, c)
	}
	return out, nil
}

func jqCandidates(ctx context.Context, program, text string, vars map[string]string) ([]candidate, error) {
	var input any
	if err := json.Unmarshal([]byte(text), &input); err != nil {
		if err := yaml.Unmarshal([]byte(text), &input); err != nil {
			return nil, fmt.Errorf("jq: document is neither JSON nor YAML: %w", err)
		}
		input = jsonCompatible(input)
	}
	q, err := gojq.Parse(program)
	if err != nil {
		return nil, fmt.Errorf("jq: %w", err)
	}
	names := make([]string, 0, len(vars))
	for k := range vars {
		names = append(names, k)
	}
	slices.Sort(names)
	varNames := make([]string, len(names))
	values := make([]any, len(names))
	for i, k := range names {
		varNames[i], values[i] = "$"+k, vars[k]
	}
	code, err := gojq.Compile(q, gojq.WithVariables(varNames))
	if err != nil {
		return nil, fmt.Errorf("jq: %w", err)
	}

	var out []candidate
	it := code.RunWithContext(ctx, input, values...)
	for {
		v, ok := it.Next()
		if !ok {
			return out, nil
		}
		if err, isErr := v.(error); isErr {
			return nil, fmt.Errorf("jq: %w", err)
		}
		obj, isObj := v.(map[string]any)
		if !isObj {
			return nil, fmt.Errorf("jq: output is %T, not an object", v)
		}
		c := candidate{vars: make(map[string]string, len(obj))}
		for k, val := range obj {
			if val == nil {
				continue // null means absent, so a later step can supply it
			}
			s, err := scalar(val)
			if err != nil {
				return nil, fmt.Errorf("jq: key %q: %w", k, err)
			}
			c.vars[k] = s
		}
		enc, err := json.Marshal(obj)
		if err != nil {
			return nil, fmt.Errorf("jq: %w", err)
		}
		c.text = string(enc)
		out = append(out, c)
	}
}

// scalar formats a jq output value that is a string, number or boolean.
func scalar(v any) (string, error) {
	switch x := v.(type) {
	case string:
		return x, nil
	case bool:
		return strconv.FormatBool(x), nil
	case int:
		return strconv.Itoa(x), nil
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), nil
	case *big.Int:
		return x.String(), nil
	}
	return "", fmt.Errorf("value %v is %T, not a string, number or boolean", v, v)
}

// jsonCompatible converts what yaml.v3 decodes into the types gojq accepts.
func jsonCompatible(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			x[k] = jsonCompatible(e)
		}
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[fmt.Sprint(k)] = jsonCompatible(e)
		}
		return m
	case []any:
		for i, e := range x {
			x[i] = jsonCompatible(e)
		}
	case uint64:
		return float64(x)
	case time.Time:
		return x.Format(time.RFC3339)
	}
	return v
}

// finish turns the final variables into a Release.
func (r *run) finish(ctx context.Context, t trail) (*Release, error) {
	fail := func(format string, args ...any) (*Release, error) {
		return nil, fmt.Errorf("%s: %s", r.e.ID, fmt.Sprintf(format, args...))
	}
	vars := t.vars
	rawURL, err := catalog.Render(r.e.URL, vars, nil)
	if err != nil {
		return fail("url: %v", err)
	}
	u, err := url.Parse(rawURL)
	if err != nil {
		return fail("url: %v", err)
	}
	if u.Scheme != "https" || u.Host == "" {
		return fail("url %q is not an https URL", rawURL)
	}
	filename := ""
	if r.e.Filename != "" {
		filename, err = catalog.Render(r.e.Filename, vars, nil)
	} else {
		filename, err = url.PathUnescape(path.Base(u.EscapedPath()))
	}
	if err != nil {
		return fail("file name: %v", err)
	}
	if !catalog.ValidFilename(filename) {
		return fail("file name %q is not a plain .iso name", filename)
	}
	version := vars["version"]
	if version == "" {
		return fail("no version variable")
	}
	if !strings.Contains(filename, version) {
		return fail("file name %q doesn't contain version %q", filename, version)
	}

	rel := &Release{EntryID: r.e.ID, Version: version, URL: rawURL, Filename: filename}
	rel.Vars = make(map[string]string, len(vars))
	for k, v := range vars {
		rel.Vars[k] = v
	}

	var doc source
	switch {
	case vars["sha512"] != "":
		rel.Checksum, doc = verify.Checksum{Algo: "sha512", Hex: strings.ToLower(vars["sha512"])}, t.docs["sha512"]
	case vars["sha256"] != "":
		rel.Checksum, doc = verify.Checksum{Algo: "sha256", Hex: strings.ToLower(vars["sha256"])}, t.docs["sha256"]
	case r.e.Checksum != nil:
		sv := make(map[string]string, len(vars)+2)
		for k, v := range vars {
			sv[k] = v
		}
		sv["url"], sv["filename"] = rawURL, filename
		rel.Checksum, doc, err = r.sidecar(ctx, sv)
		if err != nil {
			return fail("%v", err)
		}
	default:
		return fail("no checksum: no sha256 or sha512 variable and no checksum sidecar")
	}
	if !rel.Checksum.Valid() {
		return fail("invalid %s checksum %q", rel.Checksum.Algo, rel.Checksum.Hex)
	}
	rel.SignedBy = doc.signer

	if sig := r.e.Signature; sig != nil {
		sv := map[string]string{"url": rawURL, "filename": filename}
		for k, v := range vars {
			if _, set := sv[k]; !set {
				sv[k] = v
			}
		}
		sigURL, err := catalog.Render(sig.URL, sv, nil)
		if err != nil {
			return fail("signature url: %v", err)
		}
		switch sig.Type {
		case catalog.SigDetachedChecksums:
			if r.opt.Verifier == nil {
				return fail("detached-checksums signature needs a verifier")
			}
			body, err := r.f.Get(ctx, sigURL)
			if err != nil {
				return fail("get %s: %v", sigURL, err)
			}
			fpr, err := r.opt.Verifier.VerifyDetached(doc.raw, body.Body)
			if err != nil {
				return nil, fmt.Errorf("%s: verify %s: %w: %w", r.e.ID, sigURL, ErrSignature, err)
			}
			rel.SignedBy = fpr
		case catalog.SigDetachedISO:
			rel.ISOSignatureURL = sigURL
		default:
			return fail("unknown signature type %q", sig.Type)
		}
	}
	return rel, nil
}

// sidecar reads the checksum for the file from the entry's sidecar document.
func (r *run) sidecar(ctx context.Context, vars map[string]string) (verify.Checksum, source, error) {
	sc := r.e.Checksum
	u, err := catalog.Render(sc.Fetch, vars, nil)
	if err != nil {
		return verify.Checksum{}, source{}, fmt.Errorf("checksum fetch: %w", err)
	}
	d, err := r.f.Get(ctx, u)
	if err != nil {
		return verify.Checksum{}, source{}, fmt.Errorf("get %s: %w", u, err)
	}
	src := source{raw: d.Body}

	if sc.Match != "" {
		re, err := compileTemplate(sc.Match, vars)
		if err != nil {
			return verify.Checksum{}, source{}, fmt.Errorf("checksum match: %w", err)
		}
		m := re.FindStringSubmatch(string(d.Body))
		if m == nil {
			return verify.Checksum{}, source{}, fmt.Errorf("checksum match found nothing in %s", u)
		}
		for _, algo := range []string{"sha512", "sha256"} {
			if i := re.SubexpIndex(algo); i >= 0 && m[i] != "" {
				return verify.Checksum{Algo: algo, Hex: strings.ToLower(m[i])}, src, nil
			}
		}
		return verify.Checksum{}, source{}, fmt.Errorf("checksum match in %s has no sha256 or sha512 group", u)
	}

	sums := verify.ParseChecksums(d.Body)
	if c, ok := sums[vars["filename"]]; ok {
		return c, src, nil
	}
	if len(sums) == 1 {
		for _, c := range sums {
			return c, src, nil
		}
	}
	return verify.Checksum{}, source{}, fmt.Errorf("%s has no checksum for %q", u, vars["filename"])
}

// CompareVersions orders version strings naturally and returns -1, 0 or +1.
// Runs of digits compare as numbers, ignoring leading zeros. Runs of letters
// compare as text. Any other character only separates runs. When one
// version's runs are a prefix of the other's, the longer version is newer.
// So 9.10 > 9.9, 2026.3a > 2026.3, and 20261115T170104Z > 20261108T000000Z.
// A digit run beats a letter run in the same position.
func CompareVersions(a, b string) int {
	for {
		ka, ra, resta := nextRun(a)
		kb, rb, restb := nextRun(b)
		switch {
		case ka == 0 && kb == 0:
			return 0
		case ka == 0:
			return -1
		case kb == 0:
			return 1
		case ka != kb:
			if ka == 'd' {
				return 1
			}
			return -1
		}
		var c int
		if ka == 'd' {
			ra, rb = strings.TrimLeft(ra, "0"), strings.TrimLeft(rb, "0")
			if c = len(ra) - len(rb); c == 0 {
				c = strings.Compare(ra, rb)
			}
		} else {
			c = strings.Compare(ra, rb)
		}
		if c != 0 {
			return min(max(c, -1), 1)
		}
		a, b = resta, restb
	}
}

// nextRun skips separators and returns the next run of digits ('d') or ASCII
// letters ('a') with the text after it. The kind is 0 when nothing is left.
func nextRun(s string) (kind byte, run, rest string) {
	class := func(c byte) byte {
		switch {
		case c >= '0' && c <= '9':
			return 'd'
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z':
			return 'a'
		}
		return 0
	}
	i := 0
	for i < len(s) && class(s[i]) == 0 {
		i++
	}
	if i == len(s) {
		return 0, "", ""
	}
	kind = class(s[i])
	j := i
	for j < len(s) && class(s[j]) == kind {
		j++
	}
	return kind, s[i:j], s[j:]
}

// MatchesPin reports whether version equals pin, or starts with pin followed
// by a character that is neither a letter nor a digit. An empty pin matches
// every version. So pin 24.04 matches 24.04 and 24.04.3, but not 24.040, and
// pin 9 matches 9.6 and 9-1, but not 90.
func MatchesPin(version, pin string) bool {
	if pin == "" || version == pin {
		return true
	}
	rest, ok := strings.CutPrefix(version, pin)
	if !ok {
		return false
	}
	r, _ := utf8.DecodeRuneInString(rest)
	return !unicode.IsLetter(r) && !unicode.IsDigit(r)
}
