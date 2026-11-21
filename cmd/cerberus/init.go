package main

import (
	"cmp"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/successful-accident/cerberus/internal/catalog"
	"github.com/successful-accident/cerberus/internal/config"
	"github.com/successful-accident/cerberus/internal/engine"
	"github.com/successful-accident/cerberus/internal/host"
	"github.com/successful-accident/cerberus/internal/library"
	"github.com/successful-accident/cerberus/internal/notify"
)

// initOpts are init's flags. An empty field means the flag wasn't given.
type initOpts struct {
	dir, storage string
	selectIDs    []string
	keep         int
	keepSet      bool
	arch, at     string
	noSchedule   bool
	sync, yes    bool
}

func defaultArch() string {
	if slices.Contains(catalog.Architectures, runtime.GOARCH) {
		return runtime.GOARCH
	}
	return ""
}

func (a *app) initCmd() *cobra.Command {
	o := initOpts{}
	cmd := &cobra.Command{
		Use:   "init",
		Short: "First-run setup: location, distros, retention, schedule, alerts",
		Long:  "First-run setup. Every question has a flag. Without a terminal, add --yes to accept the defaults for the questions you didn't answer with a flag.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			o.keepSet = cmd.Flags().Changed("keep")
			return a.runInit(cmd, o)
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.dir, "dir", "", "keep ISOs in this folder (directory mode)")
	f.StringVar(&o.storage, "storage", "", "keep ISOs in this Proxmox VE storage")
	f.StringSliceVar(&o.selectIDs, "select", nil, "comma-separated distro IDs to maintain")
	f.IntVar(&o.keep, "keep", 1, "versions to keep per distro")
	f.StringVar(&o.arch, "arch", defaultArch(), "architecture to download: amd64 or arm64")
	f.StringVar(&o.at, "schedule", "", "install the daily sync at this time, HH:MM")
	f.BoolVar(&o.noSchedule, "no-schedule", false, "don't install the daily sync")
	f.BoolVar(&o.sync, "sync", false, "run the first sync when setup ends")
	f.BoolVar(&o.yes, "yes", false, "don't ask; accept the defaults")
	return cmd
}

var topicRE = regexp.MustCompile(`^[-_A-Za-z0-9]{1,64}$`)

func validTopic(s string) error {
	if !topicRE.MatchString(s) {
		return errors.New("use 1 to 64 letters, digits, - or _")
	}
	return nil
}

func validKeep(s string) error {
	if n, err := strconv.Atoi(s); err != nil || n < 1 {
		return errors.New("enter a whole number, 1 or more")
	}
	return nil
}

func (a *app) runInit(cmd *cobra.Command, o initOpts) error {
	out := cmd.OutOrStdout()
	u := a.ui(cmd)
	ask := a.interactive() && !o.yes

	if _, err := config.Load(a.configPath); !errors.Is(err, config.ErrNoConfig) {
		if !ask && !o.yes {
			return errors.New("already set up; use cerberus settings")
		}
		if ask {
			ok, err := u.confirm("cerberus is already set up. Start over and replace your settings?", false)
			if err != nil {
				return err
			}
			if !ok {
				fmt.Fprintln(out, "Left your settings as they were.")
				return nil
			}
		}
	}
	if !ask && !o.yes {
		return errors.New("init asks questions, so run it in a terminal, or add --yes to accept the defaults")
	}
	if !slices.Contains(catalog.Architectures, o.arch) {
		return fmt.Errorf("--arch must be one of %v", catalog.Architectures)
	}
	cat, err := a.loadCatalog()
	if err != nil {
		return err
	}
	for _, id := range o.selectIDs {
		if _, ok := cat.Get(id); !ok {
			return fmt.Errorf("%q isn't in the catalog; see cerberus catalog", id)
		}
	}
	info, run, err := a.detect(cmd)
	if err != nil {
		return err
	}

	tgt, err := a.chooseLocation(cmd, u, info, run, locationReq{dir: o.dir, storage: o.storage, ask: ask, useDefault: o.yes})
	if err != nil {
		return err
	}
	if tgt.Mode == library.ModeDir {
		if err := ensureDir(u, ask, tgt.Dir); err != nil {
			return err
		}
	}

	ids := o.selectIDs
	if len(ids) == 0 && ask {
		if ids, err = a.pickDistros(u, cat, nil); err != nil {
			return err
		}
	}
	keep := o.keep
	if !o.keepSet && ask {
		s, err := u.input("Versions to keep per distro", strconv.Itoa(keep), validKeep)
		if err != nil {
			return err
		}
		keep, _ = strconv.Atoi(s)
	}

	cfg := config.New(o.arch)
	cfg.Mode, cfg.Dir, cfg.Storage, cfg.Keep = tgt.Mode, tgt.Dir, tgt.Storage, keep
	cfg.Schedule = cmp.Or(o.at, cfg.Schedule)
	cfg.Add(ids...)
	if err := cfg.Save(a.configPath); err != nil {
		return err
	}
	fmt.Fprintf(out, "Saved %s. Library: %s. %d distros, keeping %d version(s) of each.\n", a.configPath, locationText(cfg, &library.State{}), len(ids), keep)
	if len(ids) == 0 {
		fmt.Fprintln(out, "No distros selected yet. Run cerberus select, or cerberus add <id>.")
	}

	if !o.noSchedule {
		install := o.at != "" || !ask
		if !install {
			if install, err = u.confirm(fmt.Sprintf("Sync every day at %s?", cfg.Schedule), true); err != nil {
				return err
			}
		}
		if install {
			if err := a.installSchedule(cmd, info, run, cfg.Schedule); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "The schedule wasn't installed (%v). Run cerberus schedule install when you can.\n", err)
			}
		}
	}
	if ask {
		if err := a.offerNtfy(cmd, u, cfg, info); err != nil {
			return err
		}
	}

	if len(ids) == 0 {
		return nil
	}
	doSync := o.sync
	if !doSync && ask {
		if doSync, err = u.confirm("Run the first sync now?", true); err != nil {
			return err
		}
	}
	if doSync {
		return a.sync(cmd, syncOpts{})
	}
	return nil
}

// ensureDir creates dir after a confirmation, if it doesn't exist.
func ensureDir(u *ui, ask bool, dir string) error {
	fi, err := os.Stat(dir)
	if err == nil {
		if !fi.IsDir() {
			return fmt.Errorf("%s exists and isn't a folder", dir)
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if ask {
		ok, err := u.confirm("Create "+dir+"?", true)
		if err != nil {
			return err
		}
		if !ok {
			return errors.New("no folder to keep ISOs in; run cerberus init again")
		}
	}
	return os.MkdirAll(dir, 0o755)
}

// pickDistros shows the catalog as a checklist labeled "<Category> · <Name>".
func (a *app) pickDistros(u *ui, cat *catalog.Catalog, current []string) ([]string, error) {
	var opts []huh.Option[string]
	for _, e := range cat.Entries {
		label := e.Name
		for _, c := range catalog.Categories {
			if c.ID == e.Category {
				label = c.Name + " · " + e.Name
			}
		}
		opts = append(opts, huh.NewOption(label, e.ID))
	}
	return u.pick("Distros to keep current", opts, current)
}

// locationReq says how chooseLocation may answer.
type locationReq struct {
	dir, storage string
	ask          bool // ask the user
	useDefault   bool // else take the default
}

// chooseLocation works out where the library goes: from the flags, from a
// question, or from the host's default.
func (a *app) chooseLocation(cmd *cobra.Command, u *ui, info *host.Info, run host.Runner, r locationReq) (engine.Target, error) {
	switch {
	case r.dir != "" && r.storage != "":
		return engine.Target{}, errors.New("use a folder or --storage, not both")
	case r.dir != "":
		return dirTarget(r.dir)
	case r.storage != "":
		return a.storageTarget(cmd, info, run, r.storage)
	case info.Kind == host.KindPVE:
		return a.askStorage(cmd, u, info, run, r)
	case r.ask:
		return a.askDir(u, info)
	case r.useDefault:
		return dirTarget(info.Suggestions[0])
	}
	return engine.Target{}, errors.New("say where the library goes: give a folder or --storage")
}

func dirTarget(dir string) (engine.Target, error) {
	if !filepath.IsAbs(dir) {
		return engine.Target{}, fmt.Errorf("%q must be an absolute path", dir)
	}
	return engine.Target{Mode: library.ModeDir, Dir: filepath.Clean(dir)}, nil
}

// pveStorages lists the node's storages that are enabled and active.
func (a *app) pveStorages(cmd *cobra.Command, info *host.Info, run host.Runner) ([]host.Storage, error) {
	all, err := host.PVEStorages(cmd.Context(), run, info.Node)
	if err != nil {
		return nil, err
	}
	return slices.DeleteFunc(all, func(s host.Storage) bool { return !s.Enabled || !s.Active }), nil
}

func (a *app) storageTarget(cmd *cobra.Command, info *host.Info, run host.Runner, id string) (engine.Target, error) {
	if info.Kind != host.KindPVE {
		return engine.Target{}, errors.New("this isn't a Proxmox VE host, so --storage doesn't apply; use a folder")
	}
	all, err := a.pveStorages(cmd, info, run)
	if err != nil {
		return engine.Target{}, err
	}
	if !slices.ContainsFunc(all, func(s host.Storage) bool { return s.ID == id }) {
		return engine.Target{}, fmt.Errorf("storage %q isn't enabled and active for ISOs on node %s", id, info.Node)
	}
	return engine.Target{Mode: library.ModePVE, Storage: id}, nil
}

const lowSpace = 50e9

func (a *app) askStorage(cmd *cobra.Command, u *ui, info *host.Info, run host.Runner, r locationReq) (engine.Target, error) {
	all, err := a.pveStorages(cmd, info, run)
	if err != nil {
		return engine.Target{}, err
	}
	if len(all) == 0 {
		return engine.Target{}, fmt.Errorf("no storage on node %s is enabled, active and takes ISOs", info.Node)
	}
	def := all[0].ID
	var opts []huh.Option[string]
	for _, s := range all {
		if s.ID == "local" {
			def = "local"
		}
		opts = append(opts, huh.NewOption(fmt.Sprintf("%s (%s free)", s.ID, engine.HumanSize(s.Avail)), s.ID))
	}
	id := def
	switch {
	case r.ask:
		if id, err = choose(u, "Which storage should hold the ISOs?", def, opts...); err != nil {
			return engine.Target{}, err
		}
	case !r.useDefault:
		return engine.Target{}, errors.New("say where the library goes: give a folder or --storage")
	}
	for _, s := range all {
		if s.ID == id && s.Avail < lowSpace {
			fmt.Fprintf(cmd.OutOrStdout(), "Warning: %s has only %s free, which fills fast with ISOs.\n", id, engine.HumanSize(s.Avail))
		}
	}
	return engine.Target{Mode: library.ModePVE, Storage: id}, nil
}

func (a *app) askDir(u *ui, info *host.Info) (engine.Target, error) {
	const other = "\x00other"
	var opts []huh.Option[string]
	for _, s := range info.Suggestions {
		opts = append(opts, huh.NewOption(s, s))
	}
	opts = append(opts, huh.NewOption("Another folder…", other))
	dir, err := choose(u, "Where should the ISOs live?", info.Suggestions[0], opts...)
	if err != nil {
		return engine.Target{}, err
	}
	if dir == other {
		dir, err = u.input("Folder (an absolute path)", "", func(s string) error {
			if !filepath.IsAbs(s) {
				return errors.New("enter an absolute path, like /srv/isos")
			}
			return nil
		})
		if err != nil {
			return engine.Target{}, err
		}
	}
	return dirTarget(dir)
}

// topicPath is where the ntfy topic lives: the config's file, else the system
// file as root, else a file beside the config.
func (a *app) topicPath(cfg *config.Config, info *host.Info) string {
	switch {
	case cfg.Ntfy.TopicFile != "":
		return cfg.Ntfy.TopicFile
	case info.Root:
		return notify.DefaultTopicFile
	}
	return filepath.Join(filepath.Dir(a.configPath), "ntfy-topic")
}

// saveTopic writes the topic to its file, readable by its owner only, and
// points the config at the file when it isn't the default. It never prints
// the topic.
func (a *app) saveTopic(cfg *config.Config, info *host.Info, topic string) error {
	path := a.topicPath(cfg, info)
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".ntfy-topic-*") // created mode 0600
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(topic + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	if path != notify.DefaultTopicFile && cfg.Ntfy.TopicFile != path {
		cfg.Ntfy.TopicFile = path
	}
	return cfg.Save(a.configPath)
}

// askTopic asks for the ntfy topic and saves it.
func (a *app) askTopic(cmd *cobra.Command, u *ui, cfg *config.Config, info *host.Info) error {
	topic, err := u.secret("ntfy topic (hidden)", validTopic)
	if err != nil {
		return err
	}
	if topic == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Couldn't read the topic without a terminal. Set it later with cerberus settings.")
		return nil
	}
	if err := a.saveTopic(cfg, info, topic); err != nil {
		return err
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Saved the topic to %s.\n", a.topicPath(cfg, info))
	return nil
}

func (a *app) offerNtfy(cmd *cobra.Command, u *ui, cfg *config.Config, info *host.Info) error {
	want, err := u.confirm("Send an ntfy alert when a sync updates or fails something?", false)
	if err != nil || !want {
		return err
	}
	return a.askTopic(cmd, u, cfg, info)
}
