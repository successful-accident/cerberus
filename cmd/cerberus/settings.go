package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/successful-accident/cerberus/internal/config"
	"github.com/successful-accident/cerberus/internal/library"
)

func (a *app) settingsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "settings",
		Short: "Change location, retention, alerts, links, reserve and schedule",
		Args:  cobra.NoArgs,
		RunE:  func(cmd *cobra.Command, _ []string) error { return a.settings(cmd) },
	}
}

// settings is a menu of small forms; each one saves as soon as it's answered.
func (a *app) settings(cmd *cobra.Command) error {
	if !a.interactive() {
		return errors.New("settings is interactive; use the individual commands")
	}
	u := a.ui(cmd)
	for {
		cfg, _, err := a.loadAll()
		if err != nil {
			return err
		}
		opts := []huh.Option[string]{
			huh.NewOption("Location", "location"),
			huh.NewOption("Default versions to keep", "keep"),
			huh.NewOption("A distro's keep or pin", "distro"),
			huh.NewOption("Alerts", "alerts"),
		}
		if cfg.Mode == library.ModeDir {
			opts = append(opts, huh.NewOption("latest/ links", "aliases"))
		}
		opts = append(opts, huh.NewOption("Free-space reserve", "reserve"), huh.NewOption("Schedule", "schedule"), huh.NewOption("Back", "back"))
		choice, err := choose(u, "Settings", "back", opts...)
		if errors.Is(err, errCancelled) || (err == nil && choice == "back") {
			return nil
		}
		if err == nil {
			err = map[string]func(*cobra.Command, *ui, *config.Config) error{
				"location": func(c *cobra.Command, _ *ui, _ *config.Config) error { return a.locationSet(c, locationOpts{}) },
				"keep":     a.setKeep, "distro": a.setDistro, "alerts": a.setAlerts,
				"aliases": a.setAliases, "reserve": a.setReserve, "schedule": a.setSchedule,
			}[choice](cmd, u, cfg)
		}
		if err != nil && !errors.Is(err, errCancelled) {
			fmt.Fprintln(cmd.ErrOrStderr(), err)
		}
	}
}

func (a *app) setKeep(cmd *cobra.Command, u *ui, cfg *config.Config) error {
	s, err := u.input("Versions to keep per distro", strconv.Itoa(cfg.Keep), validKeep)
	if err != nil {
		return err
	}
	cfg.Keep, _ = strconv.Atoi(s)
	return cfg.Save(a.configPath)
}

func (a *app) setDistro(cmd *cobra.Command, u *ui, cfg *config.Config) error {
	if len(cfg.Selected) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No distros selected yet.")
		return nil
	}
	cat, err := a.loadCatalog()
	if err != nil {
		return err
	}
	var opts []huh.Option[string]
	for _, s := range cfg.Selected {
		name := s.ID
		if e, ok := cat.Get(s.ID); ok {
			name = e.Name
		}
		opts = append(opts, huh.NewOption(name, s.ID))
	}
	id, err := choose(u, "Which distro?", cfg.Selected[0].ID, opts...)
	if err != nil {
		return err
	}
	sel := cfg.Selection(id)
	cur := ""
	if sel.Keep > 0 {
		cur = strconv.Itoa(sel.Keep)
	}
	k, err := u.input(fmt.Sprintf("Versions to keep (blank for the default, %d)", cfg.Keep), cur, func(s string) error {
		if s == "" {
			return nil
		}
		return validKeep(s)
	})
	if err != nil {
		return err
	}
	pin, err := u.input("Pin to a version series, like 24.04 (blank for none)", sel.Pin, nil)
	if err != nil {
		return err
	}
	sel.Keep, _ = strconv.Atoi(k)
	sel.Pin = strings.TrimSpace(pin)
	return cfg.Save(a.configPath)
}

func (a *app) setAlerts(cmd *cobra.Command, u *ui, cfg *config.Config) error {
	server, err := u.input("ntfy server (blank for ntfy.sh)", cfg.Ntfy.Server, func(s string) error {
		if s != "" && !strings.HasPrefix(s, "https://") {
			return errors.New("the server must start with https://")
		}
		return nil
	})
	if err != nil {
		return err
	}
	cfg.Ntfy.Server = server
	if err := cfg.Save(a.configPath); err != nil {
		return err
	}
	info, _, err := a.detect(cmd)
	if err != nil {
		return err
	}
	_, statErr := os.Stat(a.topicPath(cfg, info))
	change, err := u.confirm("Set the ntfy topic?", statErr != nil)
	if err != nil || !change {
		return err
	}
	return a.askTopic(cmd, u, cfg, info)
}

func (a *app) setAliases(cmd *cobra.Command, u *ui, cfg *config.Config) error {
	on, err := u.confirm("Keep a latest/ link to each distro's newest ISO?", cfg.Aliases)
	if err != nil {
		return err
	}
	cfg.Aliases = on
	return cfg.Save(a.configPath)
}

func (a *app) setReserve(cmd *cobra.Command, u *ui, cfg *config.Config) error {
	number := func(max float64) func(string) error {
		return func(s string) error {
			if f, err := strconv.ParseFloat(s, 64); err != nil || f < 0 || f > max {
				return fmt.Errorf("enter a number from 0 to %g", max)
			}
			return nil
		}
	}
	pct, err := u.input("Keep this percent of the disk free", strconv.FormatFloat(cfg.Reserve.Percent, 'f', -1, 64), number(90))
	if err != nil {
		return err
	}
	gb, err := u.input("But at least this many GB", strconv.FormatFloat(cfg.Reserve.MinGB, 'f', -1, 64), number(1e6))
	if err != nil {
		return err
	}
	cfg.Reserve.Percent, _ = strconv.ParseFloat(pct, 64)
	cfg.Reserve.MinGB, _ = strconv.ParseFloat(gb, 64)
	return cfg.Save(a.configPath)
}

func (a *app) setSchedule(cmd *cobra.Command, u *ui, cfg *config.Config) error {
	action, err := choose(u, "Schedule", "install",
		huh.NewOption("Install, or change the time", "install"), huh.NewOption("Remove", "remove"))
	if err != nil {
		return err
	}
	if action == "remove" {
		return a.scheduleRemove(cmd)
	}
	at, err := u.input("Time of day, HH:MM", cfg.Schedule, nil)
	if err != nil {
		return err
	}
	return a.scheduleInstall(cmd, at)
}
