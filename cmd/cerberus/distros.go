package main

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/successful-accident/cerberus/internal/config"
	"github.com/successful-accident/cerberus/internal/engine"
	"github.com/successful-accident/cerberus/internal/library"
)

func (a *app) selectCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "select",
		Short: "Pick the distros to keep current, from a checklist",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return a.selectDistros(cmd) },
	}
}

func (a *app) selectDistros(cmd *cobra.Command) error {
	if !a.interactive() {
		return errors.New("select is interactive; use cerberus add and cerberus remove")
	}
	cfg, cat, err := a.loadAll()
	if err != nil {
		return err
	}
	chosen, err := a.pickDistros(a.ui(cmd), cat, cfg.IDs())
	if err != nil {
		return err
	}
	var added, removed []string
	for _, e := range cat.Entries {
		sel, was := slices.Contains(chosen, e.ID), cfg.Selection(e.ID) != nil
		switch {
		case sel && !was:
			added = append(added, e.ID)
		case !sel && was:
			removed = append(removed, e.ID)
		}
	}
	cfg.Add(added...)
	cfg.Remove(removed...)
	if err := cfg.Save(a.configPath); err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	if len(added)+len(removed) == 0 {
		fmt.Fprintln(out, "No changes.")
	}
	if len(added) > 0 {
		fmt.Fprintf(out, "Added: %s. Run cerberus sync to download them.\n", strings.Join(added, ", "))
	}
	if len(removed) > 0 {
		fmt.Fprintf(out, "Removed: %s.\nDeselecting doesn't delete files. To delete them too, run cerberus remove %s --delete-files.\n",
			strings.Join(removed, ", "), strings.Join(removed, " "))
	}
	return nil
}

func (a *app) addCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "add <id>...",
		Short: "Select distros by ID",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, ids []string) error {
			cfg, cat, err := a.loadAll()
			if err != nil {
				return err
			}
			for _, id := range ids {
				if _, ok := cat.Get(id); !ok {
					return fmt.Errorf("%q isn't in the catalog; see cerberus catalog", id)
				}
			}
			added := cfg.Add(ids...)
			if err := cfg.Save(a.configPath); err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			if len(added) == 0 {
				fmt.Fprintln(out, "Already selected.")
				return nil
			}
			fmt.Fprintf(out, "Added: %s. Run cerberus sync to download them.\n", strings.Join(added, ", "))
			return nil
		},
	}
}

func (a *app) removeCmd() *cobra.Command {
	var deleteFiles bool
	cmd := &cobra.Command{
		Use:   "remove <id>...",
		Short: "Deselect distros, and optionally delete their files",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, ids []string) error {
			return a.remove(cmd, ids, deleteFiles)
		},
	}
	cmd.Flags().BoolVar(&deleteFiles, "delete-files", false, "also delete the ISOs cerberus downloaded for them")
	return cmd
}

func (a *app) remove(cmd *cobra.Command, ids []string, deleteFiles bool) error {
	cfg, cat, err := a.loadAll()
	if err != nil {
		return err
	}
	st, err := library.LoadState(a.paths().State())
	if err != nil {
		return err
	}
	for _, id := range ids {
		if cfg.Selection(id) == nil && st.Entries[id] == nil {
			return fmt.Errorf("%q isn't selected", id)
		}
	}
	out := cmd.OutOrStdout()
	removed := cfg.Remove(ids...)
	env, err := a.env(cmd, cfg, cat, out, nil)
	if err != nil {
		return err
	}
	s, err := engine.Open(cmd.Context(), env, engine.OpenOptions{})
	if err != nil {
		return err
	}
	defer s.Close()
	if len(removed) > 0 {
		if err := cfg.Save(a.configPath); err != nil {
			return err
		}
	}
	deleted, err := s.Forget(ids, deleteFiles)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "Removed: %s.\n", strings.Join(ids, ", "))
	if deleteFiles {
		for _, rel := range deleted {
			fmt.Fprintln(out, "Deleted "+s.Layout.Abs(rel))
		}
		if len(deleted) == 0 {
			fmt.Fprintln(out, "No files to delete.")
		}
	}
	return nil
}

func (a *app) keepCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "keep <id> <n>",
		Short: "Keep the newest n versions of a distro",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := strconv.Atoi(args[1])
			if err != nil || n < 1 {
				return fmt.Errorf("%q must be a whole number, 1 or more", args[1])
			}
			return a.editSelection(cmd, args[0], func(s *config.Selection) { s.Keep = n },
				fmt.Sprintf("%s: keeping the newest %d.", args[0], n))
		},
	}
}

func (a *app) pinCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "pin <id> [prefix]",
		Short: "Hold a distro to one version series, like 24.04; without a prefix, unpin",
		Args:  cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			pin, msg := "", args[0]+": unpinned."
			if len(args) == 2 {
				pin, msg = args[1], fmt.Sprintf("%s: pinned to %s.", args[0], args[1])
			}
			return a.editSelection(cmd, args[0], func(s *config.Selection) { s.Pin = pin }, msg)
		},
	}
}

// editSelection changes one selected distro and saves the config.
func (a *app) editSelection(cmd *cobra.Command, id string, edit func(*config.Selection), msg string) error {
	cfg, _, err := a.loadAll()
	if err != nil {
		return err
	}
	sel := cfg.Selection(id)
	if sel == nil {
		return fmt.Errorf("%q isn't selected; add it with cerberus add %s", id, id)
	}
	edit(sel)
	if err := cfg.Save(a.configPath); err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), msg)
	return nil
}
