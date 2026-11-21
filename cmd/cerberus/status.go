package main

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/successful-accident/cerberus/internal/catalog"
	"github.com/successful-accident/cerberus/internal/config"
	"github.com/successful-accident/cerberus/internal/download"
	"github.com/successful-accident/cerberus/internal/engine"
	"github.com/successful-accident/cerberus/internal/host"
	"github.com/successful-accident/cerberus/internal/library"
)

func (a *app) statusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show the library, with a menu in a terminal",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return a.status(cmd) },
	}
}

// status prints the status screen. In a terminal it then shows the menu
// until the user quits, and with no config it runs the init wizard first.
func (a *app) status(cmd *cobra.Command) error {
	cfg, cat, err := a.loadAll()
	if errors.Is(err, config.ErrNoConfig) && a.interactive() {
		if err = a.runInit(cmd, initOpts{keep: 1, arch: defaultArch()}); err != nil {
			return err
		}
		cfg, cat, err = a.loadAll()
	}
	for err == nil {
		if err = a.printStatus(cmd, cfg, cat); err != nil || !a.interactive() {
			return err
		}
		var next string
		if next, err = a.menu(cmd); err != nil || next == "quit" {
			if errors.Is(err, errCancelled) {
				err = nil
			}
			return err
		}
		if err = a.runMenuChoice(cmd, next); err != nil && !errors.Is(err, errCancelled) {
			fmt.Fprintln(cmd.ErrOrStderr(), err)
		}
		fmt.Fprintln(cmd.OutOrStdout())
		cfg, cat, err = a.loadAll()
	}
	return err
}

func (a *app) menu(cmd *cobra.Command) (string, error) {
	return choose(a.ui(cmd), "What next?", "sync",
		huh.NewOption("Sync now", "sync"),
		huh.NewOption("Check only", "check"),
		huh.NewOption("Choose distros", "select"),
		huh.NewOption("Settings", "settings"),
		huh.NewOption("Quit", "quit"))
}

func (a *app) runMenuChoice(cmd *cobra.Command, choice string) error {
	switch choice {
	case "sync":
		return a.sync(cmd, syncOpts{})
	case "check":
		return a.sync(cmd, syncOpts{dryRun: true})
	case "select":
		return a.selectDistros(cmd)
	}
	return a.settings(cmd)
}

// locationText describes where the library is.
func locationText(cfg *config.Config, st *library.State) string {
	if cfg.Mode == library.ModePVE {
		if st.Root != "" {
			return fmt.Sprintf("storage %s (%s)", cfg.Storage, st.Root)
		}
		return "storage " + cfg.Storage
	}
	return cfg.Dir
}

// statusLabel is a row's status column.
func statusLabel(status string) string {
	switch status {
	case library.StatusOK:
		return "✓ up to date"
	case library.StatusUpdated:
		return "↑ updated"
	case library.StatusFailed:
		return "✗ failed"
	case library.StatusRegressed:
		return "↓ upstream older"
	}
	return "· not synced yet"
}

func (a *app) printStatus(cmd *cobra.Command, cfg *config.Config, cat *catalog.Catalog) error {
	out := cmd.OutOrStdout()
	info, run, err := a.detect(cmd)
	if err != nil {
		return err
	}
	st, err := library.LoadState(a.paths().State())
	if err != nil {
		return err
	}
	sched, err := host.ScheduleStatus(cmd.Context(), a.hostRoot, run, info)
	if err != nil {
		sched = "schedule unknown: " + err.Error()
	}
	fmt.Fprintf(out, "cerberus %s · %s · %s\n%s\n\n", version, cmp.Or(info.Name, info.Hostname, "Linux"), locationText(cfg, st), sched)

	rows := engine.Rows(cfg, cat, st)
	if len(rows) == 0 {
		fmt.Fprintln(out, "No distros selected yet. Run cerberus select, or cerberus add <id>.")
	} else {
		a.printTable(out, rows, time.Now())
	}
	a.printFooter(out, cfg, st)
	return nil
}

// printTable prints the rows with each failure's message and kept files under it.
func (a *app) printTable(out io.Writer, rows []engine.Row, now time.Time) {
	dash := func(s string) string { return cmp.Or(s, "-") }
	cells := [][]string{{"DISTRO", "VERSION", "LAST CHECK", "STATUS", "SIZE", "KEPT"}}
	for _, r := range rows {
		size, kept := "-", "-"
		if r.Kept > 0 {
			size, kept = engine.HumanSize(r.Size), fmt.Sprint(r.Kept)
		}
		cells = append(cells, []string{r.Name, dash(r.Version), lastCheck(r.LastCheck, now), statusLabel(r.Status), size, kept})
	}
	var widths [6]int
	for _, row := range cells {
		for i, c := range row {
			widths[i] = max(widths[i], lipgloss.Width(c))
		}
	}
	line := func(row []string, status string) {
		var sb strings.Builder
		for i, c := range row {
			if i == len(row)-1 {
				sb.WriteString(c)
				break
			}
			c += strings.Repeat(" ", widths[i]-lipgloss.Width(c))
			if i == 3 {
				switch status {
				case library.StatusUpdated:
					c = a.paint(bronze, c)
				case library.StatusFailed:
					c = a.paint(ember, c)
				}
			}
			sb.WriteString(c + "  ")
		}
		fmt.Fprintln(out, sb.String())
	}
	line(cells[0], "")
	for i, r := range rows {
		line(cells[i+1], r.Status)
		if (r.Status == library.StatusFailed || r.Status == library.StatusRegressed) && r.Message != "" {
			fmt.Fprintln(out, "  "+r.Message)
		}
		for _, n := range r.Notes {
			fmt.Fprintln(out, "  kept "+n)
		}
	}
}

// printFooter prints the space totals, unless the library folder doesn't exist.
func (a *app) printFooter(out io.Writer, cfg *config.Config, st *library.State) {
	l := library.Layout{Mode: cmp.Or(st.Mode, cfg.Mode), Root: st.Root, Aliases: cfg.Aliases}
	if l.Root == "" && cfg.Mode == library.ModeDir {
		l.Root = cfg.Dir
	}
	if l.Root == "" {
		return
	}
	if _, err := os.Stat(l.Root); err != nil {
		return
	}
	u, err := library.DiskUsage(l, st)
	if err != nil {
		return
	}
	reserve := download.Reserve(u.Total, cfg.Reserve.Percent, cfg.Reserve.MinBytes())
	fmt.Fprintf(out, "\nmanaged %s · other files %s · free %s, %s held in reserve\n",
		engine.HumanSize(u.Managed), engine.HumanSize(u.Other), engine.HumanSize(int64(u.Avail)), engine.HumanSize(int64(reserve)))
}
