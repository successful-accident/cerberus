package main

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/successful-accident/cerberus/internal/config"
	"github.com/successful-accident/cerberus/internal/engine"
	"github.com/successful-accident/cerberus/internal/host"
	"github.com/successful-accident/cerberus/internal/library"
	"github.com/successful-accident/cerberus/internal/notify"
)

type syncOpts struct {
	ids                     []string
	dryRun, quiet, takeOver bool
}

func (a *app) syncCmd() *cobra.Command {
	var o syncOpts
	cmd := &cobra.Command{
		Use:   "sync [id...]",
		Short: "Update every selected distro now",
		RunE: func(cmd *cobra.Command, ids []string) error {
			o.ids = ids
			return a.sync(cmd, o)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&o.dryRun, "dry-run", false, "only report what would change; write nothing")
	f.BoolVar(&o.quiet, "quiet", false, "print only failures, for the systemd timer")
	f.BoolVar(&o.takeOver, "take-over", false, "manage a library another host has claimed")
	return cmd
}

func (a *app) checkCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "check [id...]",
		Short: "Report what a sync would do, without changing anything",
		RunE: func(cmd *cobra.Command, ids []string) error {
			return a.sync(cmd, syncOpts{ids: ids, dryRun: true})
		},
	}
}

// sync runs a sync, or with dryRun only a check, and prints a line per distro.
func (a *app) sync(cmd *cobra.Command, o syncOpts) error {
	ctx, out := cmd.Context(), cmd.OutOrStdout()
	cfg, cat, err := a.loadAll()
	if err != nil {
		return err
	}
	if len(cfg.Selected) == 0 {
		fmt.Fprintln(out, "No distros selected yet. Run cerberus select, or cerberus add <id>.")
		return nil
	}
	con := &console{w: out}
	var log io.Writer
	if !o.quiet {
		log = con
	}
	var progress func(string, int64, int64)
	if a.interactive() {
		progress = con.progress
	}
	env, err := a.env(cmd, cfg, cat, log, progress)
	if err != nil {
		return err
	}

	var rep *engine.Report
	var syncErr error
	if o.dryRun {
		st, err := library.LoadState(env.Paths.State())
		if err != nil {
			return err
		}
		if rep, err = engine.Check(ctx, env, st, o.ids); err != nil {
			return err
		}
	} else {
		s, err := engine.Open(ctx, env, engine.OpenOptions{TakeOver: o.takeOver})
		if err != nil {
			// A run that can't even start, such as on an inactive storage,
			// is a failure the owner needs to hear about. Another sync
			// holding the lock isn't.
			if !errors.Is(err, library.ErrLocked) {
				a.notifyReport(cmd, cfg, env.Host, &engine.Report{Stopped: err})
			}
			return err
		}
		defer s.Close()
		if !o.quiet {
			for _, n := range s.Notes {
				fmt.Fprintln(con, "repaired: "+n)
			}
		}
		if rep, syncErr = s.Sync(ctx, o.ids); rep == nil {
			return syncErr
		}
	}

	failed := a.printReport(con, rep, o.quiet)
	if !o.dryRun {
		a.notifyReport(cmd, cfg, env.Host, rep)
	}
	switch {
	case syncErr != nil:
		return syncErr
	case rep.Stopped != nil:
		return fmt.Errorf("the run stopped early: %w", rep.Stopped)
	case failed > 0:
		return fmt.Errorf("%d of %d distros failed", failed, len(rep.Results))
	}
	return nil
}

// printReport prints one line per distro, or with quiet only the failures.
// It returns the number of failures.
func (a *app) printReport(w io.Writer, rep *engine.Report, quiet bool) (failed int) {
	for _, r := range rep.Results {
		if r.Status == library.StatusFailed {
			failed++
		} else if quiet {
			continue
		}
		fmt.Fprintln(w, a.resultLine(r))
	}
	if rep.Stopped != nil {
		fmt.Fprintln(w, a.paint(ember, "✗ the run stopped early: "+rep.Stopped.Error()))
	}
	return failed
}

func (a *app) resultLine(r engine.Result) string {
	from := cmp.Or(r.From, "new")
	switch r.Status {
	case library.StatusUpdated:
		line := fmt.Sprintf("↑ %s  %s → %s", r.Name, from, r.To)
		if r.Message != "" {
			line += "  (" + r.Message + ")"
		}
		return a.paint(bronze, line)
	case engine.StatusAvailable:
		return a.paint(bronze, fmt.Sprintf("↑ %s  %s → %s available", r.Name, from, r.To))
	case library.StatusOK:
		return fmt.Sprintf("✓ %s  %s is up to date", r.Name, r.To)
	case library.StatusFailed:
		return a.paint(ember, fmt.Sprintf("✗ %s  %s", r.Name, r.Message))
	case library.StatusRegressed:
		return fmt.Sprintf("↓ %s  %s", r.Name, r.Message)
	}
	return fmt.Sprintf("· %s  %s", r.Name, r.Status)
}

// notifyReport sends the ntfy summary when something changed and a topic file
// exists. A failure to send is printed and nothing more.
func (a *app) notifyReport(cmd *cobra.Command, cfg *config.Config, info *host.Info, rep *engine.Report) {
	if !rep.Changed() {
		return
	}
	file := cmp.Or(cfg.Ntfy.TopicFile, notify.DefaultTopicFile)
	if _, err := os.Stat(file); err != nil {
		return
	}
	errw := cmd.ErrOrStderr()
	if w := notify.TopicFileWarning(file); w != "" {
		fmt.Fprintln(errw, w)
	}
	n := &notify.Ntfy{Server: cfg.Ntfy.Server, TopicFile: file}
	if err := n.Send(cmd.Context(), rep.Message(info.Hostname)); err != nil {
		fmt.Fprintln(errw, "couldn't send the alert:", err)
	}
}
