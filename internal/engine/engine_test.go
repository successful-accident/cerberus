package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/successful-accident/cerberus/internal/catalog"
	"github.com/successful-accident/cerberus/internal/config"
	"github.com/successful-accident/cerberus/internal/download"
	"github.com/successful-accident/cerberus/internal/host"
	"github.com/successful-accident/cerberus/internal/library"
	"github.com/successful-accident/cerberus/internal/notify"
)

// ---------------------------------------------------------------- fake mirror

type mirror struct {
	mu      sync.Mutex
	files   map[string][]byte
	etags   map[string]string
	gets    map[string]int
	ranged  map[string]int
	cutOnce map[string]int // path → bytes to send before dropping the connection, once
	srv     *httptest.Server
}

func newMirror(t *testing.T) *mirror {
	m := &mirror{files: map[string][]byte{}, etags: map[string]string{}, gets: map[string]int{},
		ranged: map[string]int{}, cutOnce: map[string]int{}}
	m.srv = httptest.NewTLSServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mirror) serve(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	body, ok := m.files[r.URL.Path]
	etag := m.etags[r.URL.Path]
	cut := m.cutOnce[r.URL.Path]
	if r.Method == http.MethodGet {
		m.gets[r.URL.Path]++
		if r.Header.Get("Range") != "" {
			m.ranged[r.URL.Path]++
		}
		delete(m.cutOnce, r.URL.Path)
	} else {
		cut = 0
	}
	m.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	if etag != "" {
		w.Header().Set("ETag", etag)
	}
	if cut > 0 && r.Header.Get("Range") == "" {
		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		w.Write(body[:cut])
		w.(http.Flusher).Flush()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			conn.Close()
		}
		return
	}
	http.ServeContent(w, r, path.Base(r.URL.Path), time.Time{}, bytes.NewReader(body))
}

func (m *mirror) put(p string, body []byte) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.files[p] = body
	m.etags[p] = fmt.Sprintf(`"%x"`, sha256.Sum256(body))
}

func (m *mirror) del(p string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.files, p)
}

func (m *mirror) getCount(p string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gets[p]
}

func isoName(v string) string { return "testos-" + v + "-amd64.iso" }

func isoBody(v string) []byte { return bytes.Repeat([]byte("testos "+v+"\n"), 20000) }

func sumHex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// release publishes versions as ISOs plus a SHA256SUMS listing them all, and
// returns the SHA256SUMS bytes.
func (m *mirror) release(versions ...string) []byte {
	var lines []string
	for _, v := range versions {
		body := isoBody(v)
		m.put("/testos/"+isoName(v), body)
		lines = append(lines, sumHex(body)+"  "+isoName(v))
	}
	sums := []byte(strings.Join(lines, "\n") + "\n")
	m.put("/testos/SHA256SUMS", sums)
	return sums
}

// ---------------------------------------------------------------- catalogs and keys

const plainEntry = `- id: testos
  name: Test OS
  category: server
  arch: {amd64: amd64}
  steps:
    - fetch: %[1]s/testos/SHA256SUMS
      match: '(?m)^(?P<sha256>[0-9a-f]{64})  (?P<file>testos-(?P<version>[0-9.]+)-{arch}\.iso)$'
  url: %[1]s/testos/{file}
`

const signedEntry = plainEntry + `  signature: {type: detached-checksums, url: '%[1]s/testos/SHA256SUMS.gpg'}
  keys: [test]
  fingerprints: ['%[2]s']
`

const clearsignedEntry = `- id: testos
  name: Test OS
  category: server
  arch: {amd64: amd64}
  steps:
    - fetch: %[1]s/testos/CHECKSUM
      clearsigned: true
      match: '(?m)^SHA256 \((?P<file>testos-(?P<version>[0-9.]+)-{arch}\.iso)\) = (?P<sha256>[0-9a-f]{64})$'
  url: %[1]s/testos/{file}
  keys: [test]
  fingerprints: ['%[2]s']
`

// unsafeEntry captures whatever path the feed names.
const unsafeEntry = `- id: testos
  name: Test OS
  category: server
  arch: {amd64: amd64}
  steps:
    - fetch: %[1]s/testos/SHA256SUMS
      match: '(?m)^(?P<sha256>[0-9a-f]{64})  (?P<file>\S+)$'
  url: %[1]s/testos/{file}
  filename: '{file}'
`

func loadCatalog(t *testing.T, yaml string, keys map[string][]byte) *catalog.Catalog {
	t.Helper()
	fsys := fstest.MapFS{"catalog/test.yaml": {Data: []byte(yaml)}}
	for name, k := range keys {
		fsys["catalog/keys/"+name+".asc"] = &fstest.MapFile{Data: k}
	}
	cat, err := catalog.Load(fsys)
	if err != nil {
		t.Fatalf("catalog.Load: %v", err)
	}
	return cat
}

var keyCfg = &packet.Config{Algorithm: packet.PubKeyAlgoEdDSA}

type testKey struct {
	ent *openpgp.Entity
	pub []byte
	fpr string
}

func newKey(t *testing.T, name string) testKey {
	t.Helper()
	e, err := openpgp.NewEntity(name, "", name+"@example.invalid", keyCfg)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Serialize(w); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return testKey{ent: e, pub: buf.Bytes(), fpr: strings.ToUpper(hex.EncodeToString(e.PrimaryKey.Fingerprint))}
}

func (k testKey) detach(t *testing.T, data []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&buf, k.ent, bytes.NewReader(data), keyCfg); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func (k testKey) clearsign(t *testing.T, text []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := clearsign.Encode(&buf, k.ent.PrivateKey, keyCfg)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(text)
	w.Close()
	return buf.Bytes()
}

// ---------------------------------------------------------------- environment

type logWriter struct{ t *testing.T }

func (w logWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// fakeRunner answers PVE commands from canned output.
type fakeRunner struct {
	mu  sync.Mutex
	out map[string]string
}

func (f *fakeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := strings.Join(append([]string{name}, args...), " ")
	if out, ok := f.out[cmd]; ok {
		return []byte(out), nil
	}
	return nil, fmt.Errorf("fake runner: unexpected command %q", cmd)
}

func newEnv(t *testing.T, m *mirror, cat *catalog.Catalog) *Env {
	t.Helper()
	dir := t.TempDir()
	cfg := config.New("amd64")
	cfg.Dir = filepath.Join(dir, "isos")
	cfg.Reserve = config.Reserve{}
	cfg.Add("testos")
	return &Env{
		Config:   cfg,
		Paths:    config.Paths{Config: filepath.Join(dir, "etc", "config.yaml"), StateDir: filepath.Join(dir, "state"), CatalogDir: filepath.Join(dir, "etc", "catalog.d")},
		Catalog:  cat,
		Host:     &host.Info{Kind: host.KindLinux, Hostname: "test", MachineID: "machine-1", Root: true},
		HostRoot: filepath.Join(dir, "hostroot"),
		Run:      &fakeRunner{},
		Client:   download.New("cerberus-test", download.WithHTTPClient(m.srv.Client())),
		Log:      logWriter{t},
	}
}

// pveEnv turns env into a Proxmox host with storage local, whose ISO folder
// is under the test's temp dir. VM 105 references vmISO, if it's not "".
func pveEnv(t *testing.T, env *Env, active bool, vmISO string) string {
	t.Helper()
	isoDir := filepath.Join(filepath.Dir(env.Paths.StateDir), "pve", "template", "iso")
	if err := os.MkdirAll(isoDir, 0o755); err != nil {
		t.Fatal(err)
	}
	act := 0
	if active {
		act = 1
	}
	env.Host = &host.Info{Kind: host.KindPVE, Hostname: "pve1", Node: "pve1", MachineID: "machine-1", Root: true}
	env.Config.Mode, env.Config.Dir, env.Config.Storage, env.Config.Aliases = library.ModePVE, "", "local", false
	env.Run = &fakeRunner{out: map[string]string{
		"pvesh get /nodes/pve1/storage --content iso --enabled 1 --output-format json": fmt.Sprintf(
			`[{"active":%d,"avail":81085388800,"content":"iso,vztmpl,backup","enabled":1,"shared":0,"storage":"local","total":100861726720,"type":"dir","used":14632755200}]`, act),
		"pvesm path local:iso/cerberus-probe.iso": isoDir + "/cerberus-probe.iso\n",
	}}
	conf := filepath.Join(env.HostRoot, "etc", "pve", "nodes", "pve1", "qemu-server")
	if err := os.MkdirAll(conf, 0o755); err != nil {
		t.Fatal(err)
	}
	if vmISO != "" {
		cfg := "boot: order=scsi0;ide2\nide2: local:iso/" + vmISO + ",media=cdrom\nmemory: 4096\n"
		if err := os.WriteFile(filepath.Join(conf, "105.conf"), []byte(cfg), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return isoDir
}

func syncOnce(t *testing.T, env *Env, o OpenOptions) *Report {
	t.Helper()
	s, err := Open(context.Background(), env, o)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer s.Close()
	rep, err := s.Sync(context.Background(), nil)
	if err != nil {
		t.Fatalf("Sync: %v", err)
	}
	return rep
}

func onlyResult(t *testing.T, rep *Report) Result {
	t.Helper()
	if len(rep.Results) != 1 {
		t.Fatalf("got %d results, want 1: %+v", len(rep.Results), rep.Results)
	}
	return rep.Results[0]
}

func loadState(t *testing.T, env *Env) *library.State {
	t.Helper()
	st, err := library.LoadState(env.Paths.State())
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func versions(st *library.State) []string {
	var vs []string
	if es := st.Entries["testos"]; es != nil {
		for _, f := range es.Files {
			vs = append(vs, f.Version)
		}
	}
	sort.Strings(vs)
	return vs
}

func wantFile(t *testing.T, p string, body []byte) {
	t.Helper()
	got, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("reading %s: %v", p, err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("%s has the wrong content", p)
	}
}

func wantGone(t *testing.T, p string) {
	t.Helper()
	if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("%s should not exist (err %v)", p, err)
	}
}

// ---------------------------------------------------------------- tests

func TestFirstSyncThenNothingToDo(t *testing.T) {
	m := newMirror(t)
	m.release("1.0")
	env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(plainEntry, m.srv.URL), nil))

	res := onlyResult(t, syncOnce(t, env, OpenOptions{}))
	if res.Status != library.StatusUpdated || res.To != "1.0" {
		t.Fatalf("first sync: %+v", res)
	}
	iso := filepath.Join(env.Config.Dir, "testos", isoName("1.0"))
	wantFile(t, iso, isoBody("1.0"))
	if target, err := os.Readlink(filepath.Join(env.Config.Dir, "latest", "testos.iso")); err != nil || !strings.HasSuffix(target, isoName("1.0")) {
		t.Errorf("latest/ link: %q, %v", target, err)
	}

	res = onlyResult(t, syncOnce(t, env, OpenOptions{}))
	if res.Status != library.StatusOK {
		t.Fatalf("second sync: %+v", res)
	}
	if n := m.getCount("/testos/" + isoName("1.0")); n != 1 {
		t.Errorf("the ISO was downloaded %d times, want 1", n)
	}
}

func TestKeepCounts(t *testing.T) {
	for _, keep := range []int{1, 2} {
		t.Run(fmt.Sprintf("keep=%d", keep), func(t *testing.T) {
			m := newMirror(t)
			m.release("1.0")
			env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(plainEntry, m.srv.URL), nil))
			env.Config.Selection("testos").Keep = keep
			syncOnce(t, env, OpenOptions{})
			m.release("1.0", "1.1")
			if res := onlyResult(t, syncOnce(t, env, OpenOptions{})); res.Status != library.StatusUpdated || res.From != "1.0" || res.To != "1.1" {
				t.Fatalf("update: %+v", res)
			}
			old := filepath.Join(env.Config.Dir, "testos", isoName("1.0"))
			want := []string{"1.1"}
			if keep == 1 {
				wantGone(t, old)
			} else {
				wantFile(t, old, isoBody("1.0"))
				want = []string{"1.0", "1.1"}
			}
			if got := versions(loadState(t, env)); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("kept %v, want %v", got, want)
			}
		})
	}
}

func TestBadChecksumKeepsOldVersion(t *testing.T) {
	m := newMirror(t)
	m.release("1.0")
	env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(plainEntry, m.srv.URL), nil))
	syncOnce(t, env, OpenOptions{})

	m.release("1.0", "1.1")
	m.put("/testos/"+isoName("1.1"), []byte("tampered")) // the listed checksum no longer matches
	res := onlyResult(t, syncOnce(t, env, OpenOptions{}))
	if res.Status != library.StatusFailed || !strings.Contains(res.Message, "checksum mismatch") {
		t.Fatalf("tampered update: %+v", res)
	}
	dir := filepath.Join(env.Config.Dir, "testos")
	wantFile(t, filepath.Join(dir, isoName("1.0")), isoBody("1.0"))
	wantGone(t, filepath.Join(dir, isoName("1.1")))
	wantGone(t, filepath.Join(dir, isoName("1.1")+".part"))
	if got := versions(loadState(t, env)); strings.Join(got, ",") != "1.0" {
		t.Errorf("kept %v, want [1.0]", got)
	}
}

func TestInterruptedDownloadResumes(t *testing.T) {
	m := newMirror(t)
	m.release("1.0")
	iso := "/testos/" + isoName("1.0")
	m.cutOnce[iso] = 50000
	env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(plainEntry, m.srv.URL), nil))

	if res := onlyResult(t, syncOnce(t, env, OpenOptions{})); res.Status != library.StatusFailed {
		t.Fatalf("cut download: %+v", res)
	}
	if st := loadState(t, env); len(st.Partials) != 1 {
		t.Fatalf("partials after the cut: %v", st.Partials)
	}
	if res := onlyResult(t, syncOnce(t, env, OpenOptions{})); res.Status != library.StatusUpdated {
		t.Fatalf("resumed download: %+v", res)
	}
	wantFile(t, filepath.Join(env.Config.Dir, "testos", isoName("1.0")), isoBody("1.0"))
	if m.ranged[iso] != 1 {
		t.Errorf("ranged requests: %d, want 1", m.ranged[iso])
	}
	if st := loadState(t, env); len(st.Partials) != 0 {
		t.Errorf("partials left: %v", st.Partials)
	}
}

func TestDetachedSignature(t *testing.T) {
	good, other := newKey(t, "good"), newKey(t, "other")
	for _, tc := range []struct {
		name string
		sig  func(sums []byte) []byte
		ok   bool
	}{
		{"valid", func(s []byte) []byte { return good.detach(t, s) }, true},
		{"wrong key", func(s []byte) []byte { return other.detach(t, s) }, false},
		{"two blocks, second allowed", func(s []byte) []byte { return append(other.detach(t, s), good.detach(t, s)...) }, true},
		{"tampered sums", func(s []byte) []byte { return good.detach(t, append([]byte("x"), s...)) }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := newMirror(t)
			sums := m.release("1.0")
			m.put("/testos/SHA256SUMS.gpg", tc.sig(sums))
			cat := loadCatalog(t, fmt.Sprintf(signedEntry, m.srv.URL, good.fpr), map[string][]byte{"test": good.pub})
			env := newEnv(t, m, cat)
			res := onlyResult(t, syncOnce(t, env, OpenOptions{}))
			iso := filepath.Join(env.Config.Dir, "testos", isoName("1.0"))
			if tc.ok {
				if res.Status != library.StatusUpdated {
					t.Fatalf("want updated: %+v", res)
				}
				if st := loadState(t, env); st.Entries["testos"].Files[0].SignedBy != good.fpr {
					t.Errorf("SignedBy = %q", st.Entries["testos"].Files[0].SignedBy)
				}
				return
			}
			if res.Status != library.StatusFailed {
				t.Fatalf("want failed: %+v", res)
			}
			wantGone(t, iso)
			if n := m.getCount("/testos/" + isoName("1.0")); n != 0 {
				t.Errorf("the ISO was downloaded %d times despite the bad signature", n)
			}
		})
	}
}

func TestClearsignedIgnoresUnsignedLines(t *testing.T) {
	key := newKey(t, "good")
	m := newMirror(t)
	m.release("1.0")
	evil := []byte("evil")
	m.put("/testos/"+isoName("9.9"), evil)
	signed := key.clearsign(t, []byte("SHA256 ("+isoName("1.0")+") = "+sumHex(isoBody("1.0"))+"\n"))
	appended := append(signed, []byte("SHA256 ("+isoName("9.9")+") = "+sumHex(evil)+"\n")...)
	m.put("/testos/CHECKSUM", appended)
	env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(clearsignedEntry, m.srv.URL, key.fpr), map[string][]byte{"test": key.pub}))

	res := onlyResult(t, syncOnce(t, env, OpenOptions{}))
	if res.Status != library.StatusUpdated || res.To != "1.0" {
		t.Fatalf("want 1.0 from the signed text: %+v", res)
	}
	if n := m.getCount("/testos/" + isoName("9.9")); n != 0 {
		t.Errorf("the unsigned 9.9 was fetched %d times", n)
	}
}

func TestPVEFlatLayoutAndVMProtection(t *testing.T) {
	m := newMirror(t)
	m.release("1.0")
	env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(plainEntry, m.srv.URL), nil))
	isoDir := pveEnv(t, env, true, isoName("1.0"))

	if res := onlyResult(t, syncOnce(t, env, OpenOptions{})); res.Status != library.StatusUpdated {
		t.Fatalf("first sync: %+v", res)
	}
	wantFile(t, filepath.Join(isoDir, isoName("1.0")), isoBody("1.0"))
	wantGone(t, filepath.Join(isoDir, "latest"))

	m.release("1.0", "1.1")
	if res := onlyResult(t, syncOnce(t, env, OpenOptions{})); res.Status != library.StatusUpdated {
		t.Fatalf("update: %+v", res)
	}
	wantFile(t, filepath.Join(isoDir, isoName("1.1")), isoBody("1.1"))
	wantFile(t, filepath.Join(isoDir, isoName("1.0")), isoBody("1.0")) // VM 105 still uses it
	es := loadState(t, env).Entries["testos"]
	if len(es.Kept) != 1 || !strings.Contains(es.Kept[0].Reason, "105") {
		t.Errorf("kept notes: %+v", es.Kept)
	}
}

func TestPVEInactiveStorageWritesNothing(t *testing.T) {
	m := newMirror(t)
	m.release("1.0")
	env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(plainEntry, m.srv.URL), nil))
	isoDir := pveEnv(t, env, false, "")
	if _, err := Open(context.Background(), env, OpenOptions{}); err == nil || !strings.Contains(err.Error(), "active") {
		t.Fatalf("Open with an inactive storage: %v", err)
	}
	if entries, _ := os.ReadDir(isoDir); len(entries) != 0 {
		t.Errorf("files written to an inactive storage: %v", entries)
	}
}

func TestPVENeedsRoot(t *testing.T) {
	m := newMirror(t)
	env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(plainEntry, m.srv.URL), nil))
	pveEnv(t, env, true, "")
	env.Host.Root = false
	if _, err := Open(context.Background(), env, OpenOptions{}); !errors.Is(err, ErrNeedRoot) {
		t.Fatalf("Open as non-root in pve mode: %v", err)
	}
}

func TestHandUploadedFiles(t *testing.T) {
	t.Run("identical is adopted and never deleted", func(t *testing.T) {
		m := newMirror(t)
		m.release("1.0")
		env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(plainEntry, m.srv.URL), nil))
		mine := filepath.Join(env.Config.Dir, "testos", isoName("1.0"))
		os.MkdirAll(filepath.Dir(mine), 0o755)
		os.WriteFile(mine, isoBody("1.0"), 0o644)
		res := onlyResult(t, syncOnce(t, env, OpenOptions{}))
		if res.Status != library.StatusUpdated || !strings.Contains(res.Message, "adopted") {
			t.Fatalf("adopt: %+v", res)
		}
		m.release("1.0", "1.1")
		syncOnce(t, env, OpenOptions{})
		wantFile(t, mine, isoBody("1.0")) // pruned from state, but the file stays
		if got := versions(loadState(t, env)); strings.Join(got, ",") != "1.1" {
			t.Errorf("kept %v", got)
		}
	})
	t.Run("different is never overwritten", func(t *testing.T) {
		m := newMirror(t)
		m.release("1.0")
		env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(plainEntry, m.srv.URL), nil))
		mine := filepath.Join(env.Config.Dir, "testos", isoName("1.0"))
		os.MkdirAll(filepath.Dir(mine), 0o755)
		os.WriteFile(mine, []byte("my own build"), 0o644)
		res := onlyResult(t, syncOnce(t, env, OpenOptions{}))
		if res.Status != library.StatusFailed || !strings.Contains(res.Message, "won't overwrite") {
			t.Fatalf("conflict: %+v", res)
		}
		wantFile(t, mine, []byte("my own build"))
		wantGone(t, mine+".part")
	})
}

func TestCrashAfterRenameIsReconciled(t *testing.T) {
	m := newMirror(t)
	m.release("1.0")
	env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(plainEntry, m.srv.URL), nil))
	// Simulate a crash after Place but before the state was saved: the file is
	// in place and the journal still says pending.
	rel := filepath.Join("testos", isoName("1.0"))
	dst := filepath.Join(env.Config.Dir, rel)
	os.MkdirAll(filepath.Dir(dst), 0o755)
	os.WriteFile(dst, isoBody("1.0"), 0o644)
	st := &library.State{Schema: 1, Mode: library.ModeDir, Root: env.Config.Dir, Entries: map[string]*library.EntryState{},
		Pending: &library.Pending{Entry: "testos", Part: rel + ".part", File: library.FileRecord{
			Version: "1.0", Rel: rel, Algo: "sha256", Hash: sumHex(isoBody("1.0")), Size: int64(len(isoBody("1.0"))), Added: time.Now()}}}
	if err := library.ClaimOwner(env.Config.Dir, "machine-1", false); err != nil {
		t.Fatal(err)
	}
	if err := st.Save(env.Paths.State()); err != nil {
		t.Fatal(err)
	}
	if res := onlyResult(t, syncOnce(t, env, OpenOptions{})); res.Status != library.StatusOK {
		t.Fatalf("after reconcile the ISO should be current: %+v", res)
	}
	if n := m.getCount("/testos/" + isoName("1.0")); n != 0 {
		t.Errorf("downloaded %d times after a reconciled crash", n)
	}
}

func TestReserveRefusesDownload(t *testing.T) {
	m := newMirror(t)
	m.release("1.0")
	env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(plainEntry, m.srv.URL), nil))
	env.Config.Reserve = config.Reserve{MinGB: 1e9} // a billion GB: no disk has that free
	res := onlyResult(t, syncOnce(t, env, OpenOptions{}))
	if res.Status != library.StatusFailed || !strings.Contains(res.Message, download.ErrNoSpace.Error()) {
		t.Fatalf("want a space failure: %+v", res)
	}
	if n := m.getCount("/testos/" + isoName("1.0")); n != 0 {
		t.Errorf("downloaded despite the reserve")
	}
}

func TestUpstreamRegressionDownloadsNothing(t *testing.T) {
	m := newMirror(t)
	m.release("1.0", "1.1")
	env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(plainEntry, m.srv.URL), nil))
	syncOnce(t, env, OpenOptions{})
	m.release("1.0") // 1.1 was pulled upstream
	res := onlyResult(t, syncOnce(t, env, OpenOptions{}))
	if res.Status != library.StatusRegressed {
		t.Fatalf("want regressed: %+v", res)
	}
	if n := m.getCount("/testos/" + isoName("1.0")); n != 0 {
		t.Errorf("downloaded the older version")
	}
}

func TestPinHoldsOlderSeries(t *testing.T) {
	m := newMirror(t)
	m.release("1.9", "2.0")
	env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(plainEntry, m.srv.URL), nil))
	env.Config.Selection("testos").Pin = "1"
	if res := onlyResult(t, syncOnce(t, env, OpenOptions{})); res.To != "1.9" {
		t.Fatalf("pinned sync: %+v", res)
	}
}

func TestUnsafeFileNameRejected(t *testing.T) {
	m := newMirror(t)
	body := isoBody("1.0")
	m.put("/testos/SHA256SUMS", []byte(sumHex(body)+"  ../../escape-1.0.iso\n"))
	m.put("/escape-1.0.iso", body)
	env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(unsafeEntry, m.srv.URL), nil))
	if res := onlyResult(t, syncOnce(t, env, OpenOptions{})); res.Status != library.StatusFailed {
		t.Fatalf("want failed: %+v", res)
	}
	wantGone(t, filepath.Join(filepath.Dir(env.Config.Dir), "escape-1.0.iso"))
}

func TestLockAndOwner(t *testing.T) {
	m := newMirror(t)
	env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(plainEntry, m.srv.URL), nil))
	s, err := Open(context.Background(), env, OpenOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), env, OpenOptions{}); !errors.Is(err, library.ErrLocked) {
		t.Errorf("second Open: %v", err)
	}
	s.Close()

	env.Host.MachineID = "machine-2"
	if _, err := Open(context.Background(), env, OpenOptions{}); !errors.Is(err, library.ErrOtherOwner) {
		t.Errorf("other host: %v", err)
	}
	s, err = Open(context.Background(), env, OpenOptions{TakeOver: true})
	if err != nil {
		t.Fatalf("take over: %v", err)
	}
	s.Close()
}

func TestRelocate(t *testing.T) {
	for _, mode := range []library.FileMode{library.FilesMove, library.FilesCopy, library.FilesLeave} {
		t.Run(string(mode), func(t *testing.T) {
			m := newMirror(t)
			m.release("1.0")
			env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(plainEntry, m.srv.URL), nil))
			syncOnce(t, env, OpenOptions{})
			oldDir := env.Config.Dir
			newDir := filepath.Join(filepath.Dir(oldDir), "moved")

			s, err := Open(context.Background(), env, OpenOptions{Resume: true})
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Relocate(context.Background(), Target{Mode: library.ModeDir, Dir: newDir}, mode, false, nil); err != nil {
				t.Fatalf("Relocate: %v", err)
			}
			s.Close()

			saved, err := config.Load(env.Paths.Config)
			if err != nil || saved.Dir != newDir {
				t.Fatalf("config after the move: %+v, %v", saved, err)
			}
			oldISO := filepath.Join(oldDir, "testos", isoName("1.0"))
			newISO := filepath.Join(newDir, "testos", isoName("1.0"))
			switch mode {
			case library.FilesMove:
				wantFile(t, newISO, isoBody("1.0"))
				wantGone(t, oldISO)
			case library.FilesCopy:
				wantFile(t, newISO, isoBody("1.0"))
				wantFile(t, oldISO, isoBody("1.0"))
			case library.FilesLeave:
				wantFile(t, oldISO, isoBody("1.0"))
				wantGone(t, newISO)
			}
			// The library now syncs at the new location: a moved or copied ISO
			// is current, a left one is downloaded again.
			want := library.StatusOK
			if mode == library.FilesLeave {
				want = library.StatusUpdated
			}
			if res := onlyResult(t, syncOnce(t, env, OpenOptions{})); res.Status != want {
				t.Errorf("sync after the move: %+v, want %s", res, want)
			}
		})
	}
}

func TestOpenRefusesUnfinishedMove(t *testing.T) {
	m := newMirror(t)
	env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(plainEntry, m.srv.URL), nil))
	st := &library.State{Schema: 1, Entries: map[string]*library.EntryState{},
		Relocation: &library.Relocation{FromMode: library.ModeDir, FromRoot: "/a", ToMode: library.ModeDir, ToRoot: "/b", Files: library.FilesMove}}
	if err := st.Save(env.Paths.State()); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(context.Background(), env, OpenOptions{}); !errors.Is(err, ErrRelocating) {
		t.Fatalf("Open during a move: %v", err)
	}
}

func TestCheckWritesNothing(t *testing.T) {
	m := newMirror(t)
	m.release("1.0")
	env := newEnv(t, m, loadCatalog(t, fmt.Sprintf(plainEntry, m.srv.URL), nil))
	rep, err := Check(context.Background(), env, &library.State{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res := onlyResult(t, rep); res.Status != StatusAvailable || res.To != "1.0" {
		t.Fatalf("check: %+v", res)
	}
	wantGone(t, env.Paths.State())
	wantGone(t, env.Config.Dir)
}

func TestReportMessageReachesNtfy(t *testing.T) {
	var got struct{ title, tags, body string }
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got.title, got.tags, got.body = r.Header.Get("Title"), r.Header.Get("Tags"), string(b)
	}))
	defer srv.Close()
	topic := filepath.Join(t.TempDir(), "topic")
	os.WriteFile(topic, []byte("cerberus-test-topic\n"), 0o600)
	rep := &Report{Results: []Result{
		{Name: "Debian netinst", Status: library.StatusUpdated, From: "13.6.0", To: "13.7.0"},
		{Name: "Kali Linux", Status: library.StatusFailed, Message: "checksum mismatch"},
		{Name: "Alpine", Status: library.StatusOK},
	}}
	if !rep.Changed() {
		t.Fatal("Changed() = false")
	}
	n := notify.Ntfy{Server: srv.URL, TopicFile: topic, Client: srv.Client()}
	if err := n.Send(context.Background(), rep.Message("pve1")); err != nil {
		t.Fatal(err)
	}
	if got.title != "pve1: cerberus" || got.tags != "warning" ||
		!strings.Contains(got.body, "Debian netinst: 13.6.0 → 13.7.0") || !strings.Contains(got.body, "Kali Linux: checksum mismatch") ||
		strings.Contains(got.body, "Alpine") {
		t.Errorf("ntfy got %+v", got)
	}
}

func TestRows(t *testing.T) {
	cat := loadCatalog(t, fmt.Sprintf(plainEntry, "https://example.invalid"), nil)
	cfg := config.New("amd64")
	cfg.Dir = "/srv/isos"
	cfg.Add("testos", "gone")
	st := &library.State{Entries: map[string]*library.EntryState{"testos": {
		Status: library.StatusOK,
		Files:  []library.FileRecord{{Version: "1.1", Size: 3}, {Version: "1.0", Size: 2}},
		Kept:   []library.KeptNote{{Rel: "testos-1.0-amd64.iso", Reason: "in use by VM 105"}},
	}}}
	rows := Rows(cfg, cat, st)
	if len(rows) != 2 || rows[0].Name != "Test OS" || rows[0].Version != "1.1" || rows[0].Size != 5 || rows[0].Kept != 2 || len(rows[0].Notes) != 1 {
		t.Errorf("row 0: %+v", rows[0])
	}
	if rows[1].Status != library.StatusNew || rows[1].Name != "gone" {
		t.Errorf("row 1: %+v", rows[1])
	}
}

func TestHumanSize(t *testing.T) {
	for n, want := range map[int64]string{-1: "unknown size", 999: "999 B", 812_000_000: "812 MB", 3_140_000_000: "3.1 GB"} {
		if got := HumanSize(n); got != want {
			t.Errorf("HumanSize(%d) = %q, want %q", n, got, want)
		}
	}
}
