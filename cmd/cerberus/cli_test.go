package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cerberus "github.com/successful-accident/cerberus"
	"github.com/successful-accident/cerberus/internal/catalog"
	"github.com/successful-accident/cerberus/internal/config"
	"github.com/successful-accident/cerberus/internal/download"
	"github.com/successful-accident/cerberus/internal/host"
)

// mirror is a fake HTTPS distro mirror with one ISO, testos-1.0-amd64.iso.
type mirror struct {
	srv    *httptest.Server
	iso    []byte
	badSum bool
}

func newMirror(t *testing.T) *mirror {
	t.Helper()
	m := &mirror{iso: bytes.Repeat([]byte("0123456789"), 300_000)} // 3 MB
	m.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/SHA256SUMS":
			sum := sha256.Sum256(m.iso)
			if m.badSum {
				sum = sha256.Sum256([]byte("something else"))
			}
			fmt.Fprintf(w, "%x  testos-1.0-amd64.iso\n", sum)
		case "/testos-1.0-amd64.iso":
			http.ServeContent(w, r, "testos.iso", time.Time{}, bytes.NewReader(m.iso))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.srv.Close)
	return m
}

// rig is one test's config, state, catalog and library folders.
type rig struct {
	t                           *testing.T
	m                           *mirror
	config, state, catalog, lib string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	m := newMirror(t)
	dir := t.TempDir()
	r := &rig{t: t, m: m, config: filepath.Join(dir, "config.yaml"), state: filepath.Join(dir, "state"),
		catalog: filepath.Join(dir, "catalog.d"), lib: filepath.Join(dir, "isos")}
	if err := os.MkdirAll(r.catalog, 0o755); err != nil {
		t.Fatal(err)
	}
	entry := fmt.Sprintf(`- id: testos
  name: Test OS
  category: lightweight
  arch: {amd64: amd64}
  steps:
    - fetch: %[1]s/SHA256SUMS
      match: '(?m)^(?P<sha256>[0-9a-f]{64})  (?P<file>testos-(?P<version>[\d.]+)-{arch}\.iso)$'
  url: %[1]s/{file}
`, m.srv.URL)
	if err := os.WriteFile(filepath.Join(r.catalog, "testos.yaml"), []byte(entry), 0o644); err != nil {
		t.Fatal(err)
	}

	swap(t, &detectHost, func(context.Context, string, host.Runner) (*host.Info, error) {
		return &host.Info{Kind: host.KindLinux, Hostname: "t", MachineID: "m", Root: true, Systemd: false,
			Suggestions: []string{"/srv/isos"}}, nil
	})
	swap(t, &newClient, func() *download.Client { return download.New("t", download.WithHTTPClient(m.srv.Client())) })
	swap(t, &isTTY, func() bool { return false })
	return r
}

func swap[T any](t *testing.T, p *T, v T) {
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

// run executes the CLI in-process and returns what it printed to stdout.
func (r *rig) run(args ...string) (string, error) { return r.runIn("", args...) }

func (r *rig) runIn(stdin string, args ...string) (string, error) {
	root := newRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&bytes.Buffer{})
	root.SetIn(strings.NewReader(stdin))
	root.SetArgs(append(args, "--config", r.config, "--state-dir", r.state, "--catalog-dir", r.catalog))
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

// mustRun runs the CLI and fails the test if it errors.
func (r *rig) mustRun(args ...string) string {
	r.t.Helper()
	out, err := r.run(args...)
	if err != nil {
		r.t.Fatalf("cerberus %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func contains(t *testing.T, out string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(out, w) {
			t.Errorf("output lacks %q:\n%s", w, out)
		}
	}
}

// initRig sets the rig up with testos selected and no reserve.
func (r *rig) initRig() {
	r.t.Helper()
	r.mustRun("init", "--dir", r.lib, "--select", "testos", "--keep", "1", "--arch", "amd64", "--no-schedule", "--yes")
	cfg, err := config.Load(r.config)
	if err != nil {
		r.t.Fatal(err)
	}
	cfg.Reserve = config.Reserve{}
	if err := cfg.Save(r.config); err != nil {
		r.t.Fatal(err)
	}
}

func (r *rig) iso() string { return filepath.Join(r.lib, "testos", "testos-1.0-amd64.iso") }

func TestLifecycle(t *testing.T) {
	r := newRig(t)

	r.initRig()
	cfg, err := config.Load(r.config)
	if err != nil || cfg.Dir != r.lib || len(cfg.Selected) != 1 || cfg.Selected[0].ID != "testos" {
		t.Fatalf("config after init: %+v, %v", cfg, err)
	}

	out := r.mustRun("status", "--plain")
	contains(t, out, "cerberus dev · t · "+r.lib, "Test OS", "not synced yet", "never")

	out = r.mustRun("sync")
	contains(t, out, "↑ Test OS  new → 1.0")
	if fi, err := os.Stat(r.iso()); err != nil || fi.Size() != int64(len(r.m.iso)) {
		t.Fatalf("ISO not in the library: %v", err)
	}
	out = r.mustRun("status", "--plain")
	contains(t, out, "DISTRO", "Test OS", "1.0", "today", "↑ updated", "3 MB", "managed 3 MB", "held in reserve")
	if strings.Contains(out, "\x1b") {
		t.Errorf("--plain output has ANSI codes:\n%q", out)
	}

	out = r.mustRun("sync")
	contains(t, out, "✓ Test OS  1.0 is up to date")
	contains(t, r.mustRun("status", "--plain"), "up to date")

	contains(t, r.mustRun("check"), "✓ Test OS  1.0 is up to date")
	contains(t, r.mustRun("sync", "--dry-run", "testos"), "✓ Test OS")
	if _, err := r.run("sync", "nosuch"); err == nil {
		t.Error("sync of an unselected distro should fail")
	}

	contains(t, r.mustRun("catalog"), "Lightweight", "* testos", "Test OS", "amd64")
	if out := r.mustRun("catalog", "--category", "server"); strings.Contains(out, "testos") {
		t.Errorf("catalog --category server lists testos:\n%s", out)
	}
	out = r.mustRun("catalog", "check", "testos")
	contains(t, out, "✓ testos amd64 1.0 testos-1.0-amd64.iso 3 MB sha256 unsigned")

	r.mustRun("keep", "testos", "2")
	r.mustRun("pin", "testos", "1")
	cfg, _ = config.Load(r.config)
	if s := cfg.Selection("testos"); s.Keep != 2 || s.Pin != "1" {
		t.Errorf("after keep and pin: %+v", s)
	}
	r.mustRun("pin", "testos")
	cfg, _ = config.Load(r.config)
	if cfg.Selection("testos").Pin != "" {
		t.Error("pin with no prefix should unpin")
	}
	for _, args := range [][]string{{"keep", "testos", "0"}, {"keep", "nosuch", "2"}, {"pin", "nosuch", "1"}} {
		if _, err := r.run(args...); err == nil {
			t.Errorf("cerberus %v should fail", args)
		}
	}

	moved := filepath.Join(filepath.Dir(r.lib), "moved")
	out = r.mustRun("location")
	contains(t, out, r.lib)
	if _, err := r.run("location", "set", moved); err == nil {
		t.Error("location set without --yes should fail when not interactive")
	}
	out = r.mustRun("location", "set", moved, "--yes")
	contains(t, out, "1 files", "[1/1] renamed testos/testos-1.0-amd64.iso", "The library is now at "+moved)
	if _, err := os.Stat(r.iso()); !os.IsNotExist(err) {
		t.Errorf("the old file is still there: %v", err)
	}
	if _, err := os.Stat(filepath.Join(moved, "testos", "testos-1.0-amd64.iso")); err != nil {
		t.Errorf("the file didn't arrive: %v", err)
	}
	contains(t, r.mustRun("status", "--plain"), moved, "Test OS", "up to date")

	out = r.mustRun("remove", "testos", "--delete-files")
	contains(t, out, "Removed: testos", "Deleted "+filepath.Join(moved, "testos", "testos-1.0-amd64.iso"))
	if _, err := os.Stat(filepath.Join(moved, "testos", "testos-1.0-amd64.iso")); !os.IsNotExist(err) {
		t.Errorf("--delete-files left the ISO: %v", err)
	}
	cfg, _ = config.Load(r.config)
	if len(cfg.Selected) != 0 {
		t.Errorf("testos is still selected: %+v", cfg.Selected)
	}
	contains(t, r.mustRun("status", "--plain"), "No distros selected")
}

func TestStatusWithoutConfig(t *testing.T) {
	r := newRig(t)
	for _, args := range [][]string{nil, {"status"}, {"sync"}} {
		out, err := r.run(args...)
		if err == nil || err.Error() != "cerberus isn't set up yet; run cerberus init" {
			t.Errorf("cerberus %v: err = %v, out = %q", args, err, out)
		}
	}
}

func TestInitRefusals(t *testing.T) {
	r := newRig(t)
	if _, err := r.run("init", "--dir", r.lib); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Errorf("init without a terminal or --yes: %v", err)
	}
	if _, err := r.run("init", "--dir", "relative", "--yes"); err == nil {
		t.Error("a relative --dir should fail")
	}
	if _, err := r.run("init", "--dir", r.lib, "--select", "nosuch", "--yes"); err == nil {
		t.Error("an unknown --select ID should fail")
	}
	if _, err := r.run("init", "--storage", "local", "--yes"); err == nil {
		t.Error("--storage on a host that isn't Proxmox VE should fail")
	}
	r.mustRun("init", "--dir", r.lib, "--no-schedule", "--yes")
	if _, err := r.run("init", "--dir", r.lib, "--no-schedule"); err == nil || err.Error() != "already set up; use cerberus settings" {
		t.Errorf("init over an existing config: %v", err)
	}
	r.mustRun("init", "--dir", r.lib, "--no-schedule", "--yes") // --yes replaces it
}

func TestSyncBadChecksum(t *testing.T) {
	r := newRig(t)
	r.initRig()
	r.m.badSum = true
	out, err := r.run("sync")
	if err == nil {
		t.Fatalf("sync with a wrong checksum should exit 1:\n%s", out)
	}
	contains(t, out, "✗ Test OS", "checksum mismatch")
	if _, err := os.Stat(r.iso()); !os.IsNotExist(err) {
		t.Errorf("a download that failed its checksum is in the library: %v", err)
	}
	contains(t, r.mustRun("status", "--plain"), "✗ failed", "checksum mismatch")
	if out, err := r.run("sync", "--quiet"); err == nil || !strings.Contains(out, "✗ Test OS") {
		t.Errorf("--quiet should still print failures and exit 1: %v\n%s", err, out)
	}
	r.m.badSum = false
	contains(t, r.mustRun("sync", "--quiet"), "")
	if _, err := os.Stat(r.iso()); err != nil {
		t.Errorf("the next sync should recover: %v", err)
	}
}

func TestQuietPrintsNothingOnSuccess(t *testing.T) {
	r := newRig(t)
	r.initRig()
	if out := r.mustRun("sync", "--quiet"); out != "" {
		t.Errorf("sync --quiet printed %q", out)
	}
}

func TestCatalogCheckFailures(t *testing.T) {
	r := newRig(t)
	// No config: the weekly CI job runs this on a bare runner.
	contains(t, r.mustRun("catalog", "check", "testos"), "✓ testos amd64")
	if out, err := r.run("catalog", "check", "testos", "--arch", "arm64"); err == nil {
		t.Errorf("nothing to check for arm64 should fail:\n%s", out)
	}
	r.m.iso = []byte("tiny")
	out, err := r.run("catalog", "check", "testos")
	if err == nil {
		t.Fatalf("an implausibly small ISO should fail:\n%s", out)
	}
	contains(t, out, "✗ testos amd64:", "implausibly small")
	if _, err := r.run("catalog", "check", "nosuch"); err == nil {
		t.Error("an unknown ID should fail")
	}
}

// installedBinary makes the schedule run a file outside any temporary
// folder, as an installed binary would be, instead of the test binary.
func installedBinary(t *testing.T) string {
	t.Helper()
	bin, err := filepath.Abs("main.go")
	if err != nil {
		t.Fatal(err)
	}
	swap(t, &executable, func() (string, error) { return bin, nil })
	return bin
}

func TestScheduleCron(t *testing.T) {
	r := newRig(t)
	installedBinary(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0o755); err != nil {
		t.Fatal(err)
	}
	swap(t, &detectHost, func(context.Context, string, host.Runner) (*host.Info, error) {
		return &host.Info{Kind: host.KindLinux, Hostname: "t", Root: true, CronD: true, Suggestions: []string{"/srv/isos"}}, nil
	})
	r.initRig()
	contains(t, r.mustRun("schedule", "status", "--host-root", root), "not scheduled")
	contains(t, r.mustRun("schedule", "install", "--at", "02:15", "--host-root", root), "daily at 02:15")
	contains(t, r.mustRun("schedule", "status", "--host-root", root), "daily at 02:15")
	if cfg, _ := config.Load(r.config); cfg.Schedule != "02:15" {
		t.Errorf("schedule in config = %q", cfg.Schedule)
	}
	if _, err := r.run("schedule", "install", "--at", "25:00", "--host-root", root); err == nil {
		t.Error("a bad time should fail")
	}
	contains(t, r.mustRun("schedule", "remove", "--host-root", root), "Removed")
	contains(t, r.mustRun("schedule", "status", "--host-root", root), "not scheduled")
}

func TestSettingsNeedsATerminal(t *testing.T) {
	r := newRig(t)
	r.initRig()
	if _, err := r.run("settings"); err == nil || err.Error() != "settings is interactive; use the individual commands" {
		t.Errorf("settings: %v", err)
	}
	if _, err := r.run("select"); err == nil {
		t.Error("select without a terminal should fail")
	}
}

// accessibleRig makes the CLI think it has a terminal, with huh's accessible
// prompts reading from piped input.
func accessibleRig(t *testing.T) *rig {
	r := newRig(t)
	swap(t, &isTTY, func() bool { return true })
	return r
}

// number is testos's position in the picker, which also lists the built-in
// catalog, so it moves as the catalog grows.
func (r *rig) number() string {
	r.t.Helper()
	cat, err := catalog.Load(cerberus.CatalogFS, r.catalog)
	if err != nil {
		r.t.Fatal(err)
	}
	for i, e := range cat.Entries {
		if e.ID == "testos" {
			return fmt.Sprint(i + 1)
		}
	}
	r.t.Fatal("testos isn't in the catalog")
	return ""
}

func TestSelectAccessible(t *testing.T) {
	r := accessibleRig(t)
	r.mustRun("init", "--dir", r.lib, "--arch", "amd64", "--no-schedule", "--yes")

	// Toggle testos, then 0 to confirm.
	toggle := r.number() + "\n0\n"
	out, err := r.runIn(toggle, "select", "--accessible")
	if err != nil {
		t.Fatalf("select: %v\n%s", err, out)
	}
	contains(t, out, "Lightweight · Test OS", "Added: testos")
	if cfg, _ := config.Load(r.config); cfg.Selection("testos") == nil {
		t.Fatal("testos wasn't selected")
	}

	out, err = r.runIn(toggle, "select", "--accessible")
	if err != nil {
		t.Fatalf("select: %v\n%s", err, out)
	}
	contains(t, out, "✓ Lightweight · Test OS", "Removed: testos", "Deselecting doesn't delete files", "--delete-files")
	if cfg, _ := config.Load(r.config); len(cfg.Selected) != 0 {
		t.Fatalf("testos is still selected: %+v", cfg.Selected)
	}

	// Confirm with nothing toggled.
	out, err = r.runIn("0\n", "select", "--accessible")
	if err != nil {
		t.Fatal(err)
	}
	contains(t, out, "No changes.")
}

func TestInitWizardAccessible(t *testing.T) {
	r := accessibleRig(t)
	// Another folder, create it; toggle testos and confirm; keep 3; then no
	// to the schedule, to ntfy and to the first sync.
	in := strings.Join([]string{"2", r.lib, "y", r.number(), "0", "3", "n", "n", "n"}, "\n") + "\n"
	out, err := r.runIn(in, "init", "--accessible", "--arch", "amd64")
	if err != nil {
		t.Fatalf("init: %v\n%s", err, out)
	}
	contains(t, out, "Where should the ISOs live?", "Another folder…", "Create "+r.lib, "Saved")
	cfg, err := config.Load(r.config)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Dir != r.lib || cfg.Keep != 3 || cfg.Selection("testos") == nil {
		t.Errorf("config: %+v", cfg)
	}
	if fi, err := os.Stat(r.lib); err != nil || !fi.IsDir() {
		t.Errorf("folder wasn't created: %v", err)
	}
}

func TestSaveTopic(t *testing.T) {
	r := newRig(t)
	a := &app{configPath: r.config}
	cfg := config.New("amd64")
	cfg.Dir = r.lib
	info := &host.Info{Root: false}
	if err := a.saveTopic(cfg, info, "secret-topic"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(r.config), "ntfy-topic")
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("topic file: %v, %v", fi, err)
	}
	saved, _ := config.Load(r.config)
	if saved.Ntfy.TopicFile != path {
		t.Errorf("config topic file = %q", saved.Ntfy.TopicFile)
	}
	if data, _ := os.ReadFile(r.config); bytes.Contains(data, []byte("secret-topic")) {
		t.Error("the topic is in the config file")
	}
}

func TestConsoleProgress(t *testing.T) {
	var out bytes.Buffer
	c := &console{w: &out}
	c.progress("testos", 0, 100e6)
	c.progress("testos", 370e6/10, 100e6)
	c.progress("testos", 37_100_000, 100e6) // same percent: no new write
	c.progress("testos", 100e6, 100e6)
	fmt.Fprintln(c, "testos: updated")
	want := "\rtestos  0%  0 B / 100 MB\rtestos  37%  37 MB / 100 MB\rtestos  100%  100 MB / 100 MB\ntestos: updated\n"
	if out.String() != want {
		t.Errorf("got %q\nwant %q", out.String(), want)
	}

	out.Reset()
	c = &console{w: &out}
	c.progress("x", 10e6, 100e6)
	fmt.Fprintln(c, "x: failed")
	if out.String() != "\rx  10%  10 MB / 100 MB\nx: failed\n" {
		t.Errorf("an open progress line should end before other output: %q", out.String())
	}
}

func TestLastCheck(t *testing.T) {
	now := time.Date(2026, 11, 21, 16, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		t    time.Time
		want string
	}{
		{time.Time{}, "never"},
		{time.Date(2026, 11, 21, 4, 41, 0, 0, time.UTC), "today 04:41"},
		{time.Date(2026, 11, 20, 23, 5, 0, 0, time.UTC), "yesterday 23:05"},
		{time.Date(2026, 1, 2, 15, 4, 0, 0, time.UTC), "Jan 2 15:04"},
	} {
		if got := lastCheck(c.t, now); got != c.want {
			t.Errorf("lastCheck(%v) = %q, want %q", c.t, got, c.want)
		}
	}
}

func TestInitNtfyTopicFileFlag(t *testing.T) {
	r := newRig(t)
	topic := filepath.Join(t.TempDir(), "my-topic")
	if err := os.WriteFile(topic, []byte("secret-topic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out := r.mustRun("init", "--dir", r.lib, "--no-schedule", "--yes", "--ntfy-topic-file", topic)
	contains(t, out, "Alerts go to the ntfy topic in "+topic)
	cfg, err := config.Load(r.config)
	if err != nil || cfg.Ntfy.TopicFile != topic {
		t.Fatalf("config topic file = %q, %v", cfg.Ntfy.TopicFile, err)
	}
	if data, _ := os.ReadFile(r.config); bytes.Contains(data, []byte("secret-topic")) || strings.Contains(out, "secret-topic") {
		t.Error("the topic leaked into the config or the output")
	}

	bad := filepath.Join(t.TempDir(), "bad-topic")
	if err := os.WriteFile(bad, []byte("not a topic!\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{bad, filepath.Join(t.TempDir(), "missing")} {
		_, err := r.run("init", "--dir", r.lib, "--no-schedule", "--yes", "--ntfy-topic-file", path)
		if err == nil || strings.Contains(err.Error(), "not a topic") {
			t.Errorf("--ntfy-topic-file %s: %v", path, err)
		}
	}
}

// cannedRunner answers host commands from canned output, and systemctl
// with nothing.
type cannedRunner map[string]string

func (c cannedRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	if out, ok := c[cmd]; ok {
		return []byte(out), nil
	}
	if name == "systemctl" {
		return nil, nil
	}
	return nil, fmt.Errorf("unexpected command %q", cmd)
}

func TestSyncAlertsWhenStorageInactive(t *testing.T) {
	r := newRig(t)
	var posts atomic.Int32
	ntfy := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { posts.Add(1) }))
	defer ntfy.Close()
	swap(t, &http.DefaultClient, ntfy.Client())

	topic := filepath.Join(t.TempDir(), "ntfy-topic")
	if err := os.WriteFile(topic, []byte("secret-topic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf("mode: pve\nstorage: nfs\narch: amd64\nkeep: 1\nschedule: \"04:30\"\nntfy: {server: %q, topic_file: %q}\nselected: [{id: testos}]\n", ntfy.URL, topic)
	if err := os.WriteFile(r.config, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	swap(t, &detectHost, func(context.Context, string, host.Runner) (*host.Info, error) {
		return &host.Info{Kind: host.KindPVE, Name: "Proxmox VE 9.0.3", Hostname: "pve", Node: "pve", MachineID: "m", Root: true, Systemd: true}, nil
	})
	swap(t, &newRunner, func() host.Runner {
		return cannedRunner{"pvesh get /nodes/pve/storage --content iso --enabled 1 --output-format json": `[{"active":0,"content":"iso","enabled":1,"shared":1,"storage":"nfs","type":"nfs"}]`}
	})

	_, err := r.run("sync", "--quiet")
	if err == nil {
		t.Fatal("sync succeeded against an inactive storage")
	}
	if posts.Load() != 1 {
		t.Errorf("sync failed (%v), but %d ntfy alerts were sent, want 1", err, posts.Load())
	}
}

func TestScheduleInstallRefusesTemporaryBinary(t *testing.T) {
	r := newRig(t)
	r.initRig()
	hostRoot := t.TempDir()
	swap(t, &detectHost, func(context.Context, string, host.Runner) (*host.Info, error) {
		return &host.Info{Kind: host.KindLinux, Hostname: "t", MachineID: "m", Root: true, Systemd: true, Suggestions: []string{"/srv/isos"}}, nil
	})
	swap(t, &newRunner, func() host.Runner { return cannedRunner{} })

	// The test binary lives in a go-build folder under the temp dir, as a
	// go run binary does.
	_, err := r.run("schedule", "install", "--host-root", hostRoot)
	if err == nil || !strings.Contains(err.Error(), "install the binary first") {
		t.Errorf("schedule install from a temporary build: %v", err)
	}
	unit := filepath.Join(hostRoot, "etc/systemd/system/cerberus.service")
	if _, err := os.Stat(unit); err == nil {
		data, _ := os.ReadFile(unit)
		t.Fatalf("the unit runs a temporary binary:\n%s", data)
	}

	// An installed binary is fine.
	bin := installedBinary(t)
	r.mustRun("schedule", "install", "--host-root", hostRoot)
	if data, err := os.ReadFile(unit); err != nil || !strings.Contains(string(data), "ExecStart="+bin+" sync --quiet") {
		t.Errorf("unit: %v\n%s", err, data)
	}
}
