package main

import (
	"cmp"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/successful-accident/cerberus/internal/host"
)

func (a *app) scheduleCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "schedule", Short: "Manage the daily sync"}
	var at string
	install := &cobra.Command{
		Use:   "install",
		Short: "Sync every day, by default at 04:30",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return a.scheduleInstall(cmd, at) },
	}
	install.Flags().StringVar(&at, "at", "", "time of day, HH:MM")
	remove := &cobra.Command{
		Use:   "remove",
		Short: "Stop the daily sync",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return a.scheduleRemove(cmd) },
	}
	status := &cobra.Command{
		Use:   "status",
		Short: "Show when the next sync runs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info, run, err := a.detect(cmd)
			if err != nil {
				return err
			}
			s, err := host.ScheduleStatus(cmd.Context(), a.hostRoot, run, info)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), s)
			return nil
		},
	}
	cmd.AddCommand(install, remove, status)
	return cmd
}

// installSchedule installs the daily job and prints what it did.
func (a *app) installSchedule(cmd *cobra.Command, info *host.Info, run host.Runner, at string) error {
	bin, err := os.Executable()
	if err != nil {
		return err
	}
	msg, err := host.InstallSchedule(cmd.Context(), a.hostRoot, run, info, bin, at)
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), msg)
	return nil
}

// scheduleInstall installs the job and remembers its time in the config.
func (a *app) scheduleInstall(cmd *cobra.Command, at string) error {
	cfg, _, err := a.loadAll()
	if err != nil {
		return err
	}
	info, run, err := a.detect(cmd)
	if err != nil {
		return err
	}
	at = cmp.Or(at, cfg.Schedule)
	if err := a.installSchedule(cmd, info, run, at); err != nil {
		return err
	}
	if at != cfg.Schedule {
		cfg.Schedule = at
		return cfg.Save(a.configPath)
	}
	return nil
}

func (a *app) scheduleRemove(cmd *cobra.Command) error {
	info, run, err := a.detect(cmd)
	if err != nil {
		return err
	}
	msg, err := host.RemoveSchedule(cmd.Context(), a.hostRoot, run, info)
	if err != nil {
		return err
	}
	fmt.Fprintln(cmd.OutOrStdout(), msg)
	return nil
}
