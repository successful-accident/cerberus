package main

import (
	"errors"
	"fmt"
	"slices"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/successful-accident/cerberus/internal/engine"
	"github.com/successful-accident/cerberus/internal/library"
)

type locationOpts struct {
	dir, storage, files string
	takeOver, yes       bool
}

func (a *app) locationCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "location",
		Short: "Show where the library lives",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, _, err := a.loadAll()
			if err != nil {
				return err
			}
			st, err := library.LoadState(a.paths().State())
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintln(out, locationText(cfg, st))
			if r := st.Relocation; r != nil {
				fmt.Fprintf(out, "A move to %s is unfinished. Run cerberus location set again with the same target to finish it.\n", r.ToRoot)
			}
			return nil
		},
	}

	var o locationOpts
	set := &cobra.Command{
		Use:   "set [dir]",
		Short: "Move the library to another folder or Proxmox VE storage",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 {
				o.dir = args[0]
			}
			return a.locationSet(cmd, o)
		},
	}
	f := set.Flags()
	f.StringVar(&o.storage, "storage", "", "move to this Proxmox VE storage")
	f.StringVar(&o.files, "files", "", "what to do with the files: move (default), copy or leave")
	f.BoolVar(&o.takeOver, "take-over", false, "use a folder another host has claimed")
	f.BoolVar(&o.yes, "yes", false, "don't ask; go ahead")
	cmd.AddCommand(set)
	return cmd
}

func (a *app) locationSet(cmd *cobra.Command, o locationOpts) error {
	ctx, out := cmd.Context(), cmd.OutOrStdout()
	ask := a.interactive() && !o.yes
	if !ask && !o.yes {
		return errors.New("location set moves files; add --yes to go ahead")
	}
	mode := library.FileMode(o.files)
	if !slices.Contains([]library.FileMode{"", library.FilesMove, library.FilesCopy, library.FilesLeave}, mode) {
		return fmt.Errorf("--files must be move, copy or leave, not %q", o.files)
	}
	cfg, cat, err := a.loadAll()
	if err != nil {
		return err
	}
	con := &console{w: out}
	env, err := a.env(cmd, cfg, cat, con, nil)
	if err != nil {
		return err
	}
	u := a.ui(cmd)
	tgt, err := a.chooseLocation(cmd, u, env.Host, env.Run, locationReq{dir: o.dir, storage: o.storage, ask: ask})
	if err != nil {
		return err
	}

	st, err := library.LoadState(env.Paths.State())
	if err != nil {
		return err
	}
	if st.Relocation == nil && mode == "" {
		mode = library.FilesMove
		if ask && len(st.Entries) > 0 {
			if mode, err = choose(u, "What should happen to the files already there?", mode,
				huh.NewOption("Move them", library.FilesMove),
				huh.NewOption("Copy them and keep the originals", library.FilesCopy),
				huh.NewOption("Leave them, and stop managing them", library.FilesLeave)); err != nil {
				return err
			}
		}
	}
	fmt.Fprintln(out, relocationPlan(st, tgt, mode))
	if ask {
		ok, err := u.confirm("Go ahead?", true)
		if err != nil {
			return err
		}
		if !ok {
			return errCancelled
		}
	}

	s, err := engine.Open(ctx, env, engine.OpenOptions{Resume: true, TakeOver: o.takeOver})
	if err != nil {
		return err
	}
	defer s.Close()
	verbs := map[string]string{library.ActRename: "renamed", library.ActCopy: "moved", library.ActCopyKeep: "copied", library.ActSkip: "left"}
	err = s.Relocate(ctx, tgt, mode, o.takeOver, func(it library.RelocItem, done, total int) {
		line := fmt.Sprintf("[%d/%d] %s %s", done, total, verbs[it.Action], it.FromRel)
		if it.Action == library.ActSkip && it.Reason != "" {
			line += " (" + it.Reason + ")"
		}
		fmt.Fprintln(con, line)
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(out, "The library is now at "+locationText(cfg, s.State))
	return nil
}

// relocationPlan says what the move will do, before it does it.
func relocationPlan(st *library.State, tgt engine.Target, mode library.FileMode) string {
	to := tgt.Dir
	if tgt.Mode == library.ModePVE {
		to = "storage " + tgt.Storage
	}
	if r := st.Relocation; r != nil {
		left := 0
		for _, it := range r.Items {
			if !it.Done {
				left++
			}
		}
		return fmt.Sprintf("An earlier move to %s was interrupted. This finishes it: %d of %d files left.", r.ToRoot, left, len(r.Items))
	}
	var n, adopted int
	var size int64
	for _, es := range st.Entries {
		for _, f := range es.Files {
			if f.Adopted {
				adopted++
				continue
			}
			n, size = n+1, size+f.Size
		}
	}
	plan := fmt.Sprintf("Moving the library to %s.", to)
	switch {
	case n == 0:
		plan += " No files have been downloaded yet, so only the setting changes."
	case mode == library.FilesLeave:
		plan += fmt.Sprintf(" %d files (%s) stay where they are, and cerberus stops managing them.", n, engine.HumanSize(size))
	case mode == library.FilesCopy:
		plan += fmt.Sprintf(" %d files (%s) are copied and checked; the originals stay.", n, engine.HumanSize(size))
	default:
		known, same := false, false
		if tgt.Mode == library.ModeDir && st.Root != "" {
			var err error
			same, err = library.SameFilesystem(st.Root, tgt.Dir)
			known = err == nil
		}
		switch {
		case known && same:
			plan += fmt.Sprintf(" %d files (%s) are renamed, which is instant.", n, engine.HumanSize(size))
		case known:
			plan += fmt.Sprintf(" %d files (%s) are copied one at a time, checked against their checksums, then deleted from the old folder.", n, engine.HumanSize(size))
		default:
			plan += fmt.Sprintf(" %d files (%s) are renamed if the target shares their filesystem, and otherwise copied, checked, then deleted from the old folder.", n, engine.HumanSize(size))
		}
	}
	if adopted > 0 {
		plan += fmt.Sprintf(" %d adopted files you uploaded yourself stay where they are.", adopted)
	}
	return plan
}
