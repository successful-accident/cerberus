package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	cerberus "github.com/successful-accident/cerberus"
	"github.com/successful-accident/cerberus/internal/catalog"
	"github.com/successful-accident/cerberus/internal/config"
	"github.com/successful-accident/cerberus/internal/download"
	"github.com/successful-accident/cerberus/internal/engine"
	"github.com/successful-accident/cerberus/internal/host"
)

// Hooks that tests replace.
var (
	detectHost = host.Detect
	newRunner  = func() host.Runner { return host.ExecRunner{} }
	newClient  = func() *download.Client {
		return download.New("cerberus/"+version, download.WithGitHubToken(os.Getenv("GITHUB_TOKEN")))
	}
	isTTY = func() bool { return isCharDevice(os.Stdin) && isCharDevice(os.Stdout) }
)

func isCharDevice(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// errCancelled means the user backed out of a question.
var errCancelled = errors.New("cancelled")

// Colors: bronze for live work, ember for failures.
var (
	bronze = lipgloss.NewStyle().Foreground(lipgloss.Color("#D3A257"))
	ember  = lipgloss.NewStyle().Foreground(lipgloss.Color("#E36B45"))
)

// app holds the global flags every command shares.
type app struct {
	configPath, stateDir, catalogDir string
	hostRoot                         string
	plain, accessible                bool
}

func newRootCmd() *cobra.Command {
	a := &app{}
	def := config.DefaultPaths(os.Geteuid() == 0)
	root := &cobra.Command{
		Use:           "cerberus",
		Short:         "Keep a library of Linux ISOs current",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		Args:          cobra.NoArgs,
		RunE:          func(cmd *cobra.Command, _ []string) error { return a.status(cmd) },
	}
	f := root.PersistentFlags()
	f.StringVar(&a.configPath, "config", def.Config, "config file")
	f.StringVar(&a.stateDir, "state-dir", def.StateDir, "folder for state and the run lock")
	f.StringVar(&a.catalogDir, "catalog-dir", def.CatalogDir, "folder with your own catalog entries")
	f.BoolVar(&a.plain, "plain", false, "no menu and no colors")
	f.BoolVar(&a.accessible, "accessible", os.Getenv("CERBERUS_ACCESSIBLE") == "1", "ask questions one line at a time, for screen readers")
	f.StringVar(&a.hostRoot, "host-root", "/", "")
	_ = f.MarkHidden("host-root")
	root.AddCommand(a.statusCmd(), a.initCmd(), a.selectCmd(), a.addCmd(), a.removeCmd(), a.keepCmd(), a.pinCmd(),
		a.syncCmd(), a.checkCmd(), a.catalogCmd(), a.locationCmd(), a.scheduleCmd(), a.settingsCmd())
	return root
}

func (a *app) paths() config.Paths {
	return config.Paths{Config: a.configPath, StateDir: a.stateDir, CatalogDir: a.catalogDir}
}

// interactive reports whether to show menus, questions and colors.
func (a *app) interactive() bool { return !a.plain && isTTY() }

func (a *app) paint(st lipgloss.Style, s string) string {
	if !a.interactive() {
		return s
	}
	return st.Render(s)
}

func (a *app) loadCatalog() (*catalog.Catalog, error) {
	return catalog.Load(cerberus.CatalogFS, a.catalogDir)
}

// loadAll loads the config, which may be config.ErrNoConfig, and the catalog.
func (a *app) loadAll() (*config.Config, *catalog.Catalog, error) {
	cfg, err := config.Load(a.configPath)
	if err != nil {
		return nil, nil, err
	}
	cat, err := a.loadCatalog()
	if err != nil {
		return nil, nil, err
	}
	return cfg, cat, nil
}

// detect inspects the host.
func (a *app) detect(cmd *cobra.Command) (*host.Info, host.Runner, error) {
	run := newRunner()
	info, err := detectHost(cmd.Context(), a.hostRoot, run)
	return info, run, err
}

// env builds the engine's environment. log may be nil.
func (a *app) env(cmd *cobra.Command, cfg *config.Config, cat *catalog.Catalog, log io.Writer, progress func(string, int64, int64)) (*engine.Env, error) {
	info, run, err := a.detect(cmd)
	if err != nil {
		return nil, err
	}
	return &engine.Env{Config: cfg, Paths: a.paths(), Catalog: cat, Host: info, HostRoot: a.hostRoot,
		Run: run, Client: newClient(), Log: log, Progress: progress}, nil
}

// console is the engine's log and its download progress on one stream. A
// progress line is rewritten in place, and any other output ends it first.
type console struct {
	w    io.Writer
	open bool
	last int64
}

func (c *console) Write(p []byte) (int, error) {
	if c.open {
		fmt.Fprintln(c.w)
		c.open = false
	}
	return c.w.Write(p)
}

// progress prints "<id>  45%  370 MB / 812 MB", once per percent.
func (c *console) progress(id string, done, total int64) {
	key := done / 1e6
	line := fmt.Sprintf("\r%s  %s", id, engine.HumanSize(done))
	if total > 0 {
		key = done * 100 / total
		line = fmt.Sprintf("\r%s  %d%%  %s / %s", id, key, engine.HumanSize(done), engine.HumanSize(total))
	}
	if c.open && key == c.last && (total <= 0 || done < total) {
		return
	}
	c.open, c.last = true, key
	fmt.Fprint(c.w, line)
	if total > 0 && done >= total {
		fmt.Fprintln(c.w)
		c.open = false
	}
}

// lastCheck formats a time as "today 15:04", "yesterday 15:04", "Jan 2 15:04",
// or "never".
func lastCheck(t, now time.Time) string {
	if t.IsZero() {
		return "never"
	}
	t = t.In(now.Location())
	switch {
	case sameDay(t, now):
		return "today " + t.Format("15:04")
	case sameDay(t, now.AddDate(0, 0, -1)):
		return "yesterday " + t.Format("15:04")
	}
	return t.Format("Jan 2 15:04")
}

func sameDay(a, b time.Time) bool {
	ya, ma, da := a.Date()
	yb, mb, db := b.Date()
	return ya == yb && ma == mb && da == db
}
