// Package config reads and writes cerberus's config file, and works out where
// cerberus keeps its own files.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/successful-accident/cerberus/internal/catalog"
	"github.com/successful-accident/cerberus/internal/library"
)

// Paths says where cerberus keeps its own files.
type Paths struct {
	Config     string // config.yaml
	StateDir   string // state.json and the run lock
	CatalogDir string // local catalog entries
}

// State returns the state file's path.
func (p Paths) State() string { return filepath.Join(p.StateDir, "state.json") }

// Lock returns the run lock's path.
func (p Paths) Lock() string { return filepath.Join(p.StateDir, "lock") }

// DefaultPaths returns the system paths when running as root, and the XDG
// paths in the user's home otherwise.
func DefaultPaths(root bool) Paths {
	if root {
		return Paths{
			Config:     "/etc/cerberus/config.yaml",
			StateDir:   "/var/lib/cerberus",
			CatalogDir: "/etc/cerberus/catalog.d",
		}
	}
	home, _ := os.UserHomeDir()
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" {
		cfg = filepath.Join(home, ".config")
	}
	state := os.Getenv("XDG_STATE_HOME")
	if state == "" {
		state = filepath.Join(home, ".local", "state")
	}
	return Paths{
		Config:     filepath.Join(cfg, "cerberus", "config.yaml"),
		StateDir:   filepath.Join(state, "cerberus"),
		CatalogDir: filepath.Join(cfg, "cerberus", "catalog.d"),
	}
}

// Config is the user's choices.
type Config struct {
	Mode     library.Mode `yaml:"mode"`              // dir or pve
	Dir      string       `yaml:"dir,omitempty"`     // the library folder, in dir mode
	Storage  string       `yaml:"storage,omitempty"` // the PVE storage ID, in pve mode
	Arch     string       `yaml:"arch"`              // amd64 or arm64
	Keep     int          `yaml:"keep"`              // default versions to keep per distro
	Aliases  bool         `yaml:"aliases"`           // latest/ links, in dir mode
	Reserve  Reserve      `yaml:"reserve"`
	Ntfy     Ntfy         `yaml:"ntfy"`
	Schedule string       `yaml:"schedule"` // daily sync time, HH:MM
	Selected []Selection  `yaml:"selected"`
}

// Reserve is the free space a sync must leave on the library's filesystem.
type Reserve struct {
	Percent float64 `yaml:"percent"`
	MinGB   float64 `yaml:"min_gb"`
}

// MinBytes returns MinGB in bytes.
func (r Reserve) MinBytes() uint64 { return uint64(r.MinGB * 1e9) }

// Ntfy configures alerts. The topic itself lives only in TopicFile.
type Ntfy struct {
	Server    string `yaml:"server,omitempty"`     // "" means https://ntfy.sh
	TopicFile string `yaml:"topic_file,omitempty"` // "" means /etc/cerberus/ntfy-topic
}

// Selection is one distro the user maintains.
type Selection struct {
	ID   string `yaml:"id"`
	Keep int    `yaml:"keep,omitempty"` // 0 means Config.Keep
	Pin  string `yaml:"pin,omitempty"`  // version prefix, such as 24.04
}

// ErrNoConfig means cerberus hasn't been set up on this host.
var ErrNoConfig = errors.New("cerberus isn't set up yet; run cerberus init")

// New returns a config with the defaults filled in.
func New(arch string) *Config {
	return &Config{Mode: library.ModeDir, Arch: arch, Keep: 1, Aliases: true,
		Reserve: Reserve{Percent: 10, MinGB: 10}, Schedule: "04:30"}
}

// Load reads the config at path. A missing file is ErrNoConfig. Unknown
// fields are errors, so a typo can't silently change behavior.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoConfig
	}
	if err != nil {
		return nil, err
	}
	c := New("")
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

const header = "# cerberus config. Change it with `cerberus settings`, or edit it by hand.\n"

// Save validates c and writes it to path atomically, creating the folder.
func (c *Config) Save(path string) error {
	if err := c.Validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.yaml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append([]byte(header), data...)); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

var hhmm = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// Validate reports the first problem with c.
func (c *Config) Validate() error {
	switch c.Mode {
	case library.ModeDir:
		if !filepath.IsAbs(c.Dir) {
			return fmt.Errorf("dir %q must be an absolute path", c.Dir)
		}
	case library.ModePVE:
		if c.Storage == "" {
			return errors.New("pve mode needs a storage")
		}
	default:
		return fmt.Errorf("mode %q must be dir or pve", c.Mode)
	}
	if !slices.Contains(catalog.Architectures, c.Arch) {
		return fmt.Errorf("arch %q must be one of %s", c.Arch, strings.Join(catalog.Architectures, ", "))
	}
	if c.Keep < 1 {
		return fmt.Errorf("keep must be at least 1, not %d", c.Keep)
	}
	if c.Reserve.Percent < 0 || c.Reserve.Percent > 90 || c.Reserve.MinGB < 0 {
		return fmt.Errorf("reserve must be 0 to 90 percent and a non-negative min_gb")
	}
	if !hhmm.MatchString(c.Schedule) {
		return fmt.Errorf("schedule %q must be HH:MM", c.Schedule)
	}
	if c.Ntfy.Server != "" && !strings.HasPrefix(c.Ntfy.Server, "https://") {
		return fmt.Errorf("ntfy server %q must be https://", c.Ntfy.Server)
	}
	seen := map[string]bool{}
	for _, s := range c.Selected {
		if s.ID == "" || seen[s.ID] {
			return fmt.Errorf("selected distro %q is empty or listed twice", s.ID)
		}
		if s.Keep < 0 {
			return fmt.Errorf("%s: keep must not be negative", s.ID)
		}
		seen[s.ID] = true
	}
	return nil
}

// Selection returns the selection for id, or nil.
func (c *Config) Selection(id string) *Selection {
	for i := range c.Selected {
		if c.Selected[i].ID == id {
			return &c.Selected[i]
		}
	}
	return nil
}

// KeepFor returns how many versions to keep for id.
func (c *Config) KeepFor(id string) int {
	if s := c.Selection(id); s != nil && s.Keep > 0 {
		return s.Keep
	}
	return c.Keep
}

// Add selects ids that aren't selected yet and returns those it added.
func (c *Config) Add(ids ...string) []string {
	var added []string
	for _, id := range ids {
		if c.Selection(id) == nil {
			c.Selected = append(c.Selected, Selection{ID: id})
			added = append(added, id)
		}
	}
	return added
}

// Remove deselects ids and returns those it removed.
func (c *Config) Remove(ids ...string) []string {
	var removed []string
	c.Selected = slices.DeleteFunc(c.Selected, func(s Selection) bool {
		if slices.Contains(ids, s.ID) {
			removed = append(removed, s.ID)
			return true
		}
		return false
	})
	return removed
}

// IDs returns the selected IDs in order.
func (c *Config) IDs() []string {
	ids := make([]string, len(c.Selected))
	for i, s := range c.Selected {
		ids[i] = s.ID
	}
	return ids
}
