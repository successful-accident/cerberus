package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/successful-accident/cerberus/internal/library"
)

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "etc", "config.yaml")
	c := New("amd64")
	c.Dir = "/srv/isos"
	c.Add("debian-netinst", "alpine-virt", "debian-netinst")
	c.Selection("alpine-virt").Keep = 2
	c.Selection("alpine-virt").Pin = "3.24"
	if err := c.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Dir != "/srv/isos" || got.Keep != 1 || !got.Aliases || got.Schedule != "04:30" {
		t.Errorf("round trip lost fields: %+v", got)
	}
	if ids := strings.Join(got.IDs(), ","); ids != "debian-netinst,alpine-virt" {
		t.Errorf("IDs = %s", ids)
	}
	if got.KeepFor("alpine-virt") != 2 || got.KeepFor("debian-netinst") != 1 {
		t.Errorf("KeepFor wrong: %d %d", got.KeepFor("alpine-virt"), got.KeepFor("debian-netinst"))
	}
	if got.Selection("alpine-virt").Pin != "3.24" {
		t.Error("pin lost")
	}
	if removed := got.Remove("alpine-virt", "nope"); len(removed) != 1 || len(got.Selected) != 1 {
		t.Errorf("Remove = %v, left %v", removed, got.Selected)
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temp files left behind: %v", entries)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Load(filepath.Join(dir, "missing.yaml")); !errors.Is(err, ErrNoConfig) {
		t.Errorf("missing file: %v", err)
	}
	for name, body := range map[string]string{
		"typo":     "mode: dir\ndir: /srv/isos\narch: amd64\nkep: 2\n",
		"relative": "mode: dir\ndir: isos\narch: amd64\n",
		"mode":     "mode: nfs\ndir: /srv/isos\narch: amd64\n",
		"arch":     "mode: dir\ndir: /srv/isos\narch: riscv64\n",
		"keep":     "mode: dir\ndir: /srv/isos\narch: amd64\nkeep: 0\n",
		"pve":      "mode: pve\narch: amd64\n",
		"schedule": "mode: dir\ndir: /srv/isos\narch: amd64\nschedule: 4:30\n",
		"ntfy":     "mode: dir\ndir: /srv/isos\narch: amd64\nntfy: {server: http://ntfy.sh}\n",
		"twice":    "mode: dir\ndir: /srv/isos\narch: amd64\nselected: [{id: a}, {id: a}]\n",
	} {
		p := filepath.Join(dir, name+".yaml")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Load(p); err == nil {
			t.Errorf("%s: Load accepted %q", name, body)
		}
	}
}

func TestDefaultPaths(t *testing.T) {
	if p := DefaultPaths(true); p.Config != "/etc/cerberus/config.yaml" || p.State() != "/var/lib/cerberus/state.json" {
		t.Errorf("root paths: %+v", p)
	}
	t.Setenv("XDG_CONFIG_HOME", "/x/cfg")
	t.Setenv("XDG_STATE_HOME", "/x/state")
	p := DefaultPaths(false)
	if p.Config != "/x/cfg/cerberus/config.yaml" || p.Lock() != "/x/state/cerberus/lock" || p.CatalogDir != "/x/cfg/cerberus/catalog.d" {
		t.Errorf("XDG paths: %+v", p)
	}
}

func TestPVEConfigValid(t *testing.T) {
	c := New("arm64")
	c.Mode, c.Storage = library.ModePVE, "local"
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
}
