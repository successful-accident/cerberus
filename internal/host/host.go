// Package host inspects the machine cerberus runs on: whether it's a
// Proxmox VE host, a file server, or plain Linux. It also covers PVE
// storages and the ISOs that VMs reference, and installs the schedule.
//
// Every function that reads the filesystem takes a root path, "/" in
// production, and every command runs through a Runner, so tests can use a
// fake host tree and fake commands.
package host

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Kind is the type of host.
type Kind string

const (
	KindPVE        Kind = "pve"
	KindFileServer Kind = "fileserver"
	KindLinux      Kind = "linux"
)

// Share is a folder the host exports.
type Share struct {
	Name  string // the Samba section name, or the export path for NFS
	Path  string
	Proto string // "smb" or "nfs"
}

// Info describes the host.
type Info struct {
	Kind      Kind
	Name      string // "Proxmox VE 9.2.1", or os-release PRETTY_NAME
	Hostname  string
	Node      string // the PVE node name, else ""
	MachineID string // /etc/machine-id
	Systemd   bool   // /run/systemd/system exists
	CronD     bool   // /etc/cron.d exists
	Root      bool   // effective UID is 0
	Shares    []Share
	// Suggestions lists dir-mode library folders, best first: <share>/isos
	// for each share, then /srv/isos.
	Suggestions []string
}

// Runner runs a command and returns its standard output.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// ExecRunner runs real commands. A failure's error includes the command
// and its trimmed standard error.
type ExecRunner struct{}

// Run implements Runner.
func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	_ = exec.CommandContext
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
}

// Detect inspects the host under root.
//   - It's a PVE host when <root>/etc/pve is a folder and <root>/usr/bin/pvesh
//     exists. Node comes from the <root>/etc/pve/local symlink
//     (nodes/<name>), and Name from `pveversion` (pve-manager/9.2.1/...).
//   - Otherwise it's a file server when <root>/etc/samba/smb.conf defines a
//     share with a path (skipping [global], [homes], [printers], [print$]
//     and printable shares), or <root>/etc/exports lists one.
//   - Otherwise it's plain Linux, named from <root>/etc/os-release.
//
// Missing files are not errors.
func Detect(ctx context.Context, root string, run Runner) (*Info, error) {
	info := &Info{
		Hostname:  hostname(),
		Systemd:   isDir(filepath.Join(root, "run/systemd/system")),
		CronD:     isDir(filepath.Join(root, "etc/cron.d")),
		Root:      os.Geteuid() == 0,
		MachineID: readTrim(filepath.Join(root, "etc/machine-id")),
	}
	info.Name = osName(root)
	switch {
	case isDir(filepath.Join(root, "etc/pve")) && exists(filepath.Join(root, "usr/bin/pvesh")):
		info.Kind = KindPVE
		info.Name = "Proxmox VE"
		if dest, err := os.Readlink(filepath.Join(root, "etc/pve/local")); err == nil {
			info.Node = filepath.Base(dest)
		}
		if out, err := run.Run(ctx, "pveversion"); err == nil {
			if m := pveVersionRE.FindSubmatch(out); m != nil {
				info.Name = "Proxmox VE " + string(m[1])
			}
		}
	default:
		info.Shares = append(sambaShares(root), nfsShares(root)...)
		if len(info.Shares) > 0 {
			info.Kind = KindFileServer
		} else {
			info.Kind = KindLinux
		}
	}
	if info.Kind == KindFileServer {
		for _, sh := range info.Shares {
			info.Suggestions = append(info.Suggestions, filepath.Join(sh.Path, "isos"))
		}
	}
	info.Suggestions = append(info.Suggestions, "/srv/isos")
	return info, nil
}

// Storage is a PVE storage that can hold ISOs.
type Storage struct {
	ID      string
	Type    string
	Content string
	Active  bool
	Enabled bool
	Shared  bool
	Total   int64
	Used    int64
	Avail   int64
}

// PVEStorages lists the node's enabled storages with iso content, running
// `pvesh get /nodes/<node>/storage --content iso --enabled 1
// --output-format json`. PVE reports active, enabled and shared as 0 or 1,
// and sizes as numbers that may be absent for inactive storages.
func PVEStorages(ctx context.Context, run Runner, node string) ([]Storage, error) {
	out, err := run.Run(ctx, "pvesh", "get", "/nodes/"+node+"/storage", "--content", "iso", "--enabled", "1", "--output-format", "json")
	if err != nil {
		return nil, err
	}
	var raw []struct {
		ID      string `json:"storage"`
		Type    string `json:"type"`
		Content string `json:"content"`
		Active  num    `json:"active"`
		Enabled num    `json:"enabled"`
		Shared  num    `json:"shared"`
		Total   num    `json:"total"`
		Used    num    `json:"used"`
		Avail   num    `json:"avail"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return nil, fmt.Errorf("decode pvesh storage list for node %s: %w", node, err)
	}
	list := make([]Storage, 0, len(raw))
	for _, r := range raw {
		list = append(list, Storage{
			ID: r.ID, Type: r.Type, Content: r.Content,
			Active: r.Active != 0, Enabled: r.Enabled != 0, Shared: r.Shared != 0,
			Total: int64(r.Total), Used: int64(r.Used), Avail: int64(r.Avail),
		})
	}
	return list, nil
}

// PVEStorageReady re-lists the node's storages and returns the named one
// only if it's enabled and active. Otherwise it returns an error that says
// which. Call it before every write: an unmounted NFS storage would
// otherwise send ISOs to the boot disk.
func PVEStorageReady(ctx context.Context, run Runner, node, storage string) (*Storage, error) {
	list, err := PVEStorages(ctx, run, node)
	if err != nil {
		return nil, err
	}
	for i := range list {
		if list[i].ID != storage {
			continue
		}
		if !list[i].Enabled {
			break
		}
		if !list[i].Active {
			return nil, fmt.Errorf("storage %q on node %q is not active; it may be unmounted", storage, node)
		}
		return &list[i], nil
	}
	return nil, fmt.Errorf("storage %q is not enabled for ISOs on node %q", storage, node)
}

// PVEISODir returns the storage's ISO folder, the directory part of `pvesm
// path <storage>:iso/cerberus-probe.iso`. That honors content-dirs
// overrides and doesn't need the file to exist.
func PVEISODir(ctx context.Context, run Runner, storage string) (string, error) {
	out, err := run.Run(ctx, "pvesm", "path", storage+":iso/cerberus-probe.iso")
	if err != nil {
		return "", err
	}
	p := strings.TrimSpace(string(out))
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("pvesm path for storage %q printed %q, not an absolute path", storage, p)
	}
	return filepath.Dir(p), nil
}

// VMISORefs maps each ISO file name on the storage to the VM IDs whose
// config mentions <storage>:iso/<name>, in any section, snapshots included.
// It reads <root>/etc/pve/nodes/*/qemu-server/*.conf, covering every node in
// a cluster.
func VMISORefs(root, storage string) (map[string][]string, error) {
	files, err := filepath.Glob(filepath.Join(root, "etc/pve/nodes/*/qemu-server/*.conf"))
	if err != nil {
		return nil, err
	}
	re := regexp.MustCompile(`(?m)(^|[^A-Za-z0-9_-])` + regexp.QuoteMeta(storage) + `:iso/([^,\s]+)`)
	refs := map[string][]string{}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		vmid := strings.TrimSuffix(filepath.Base(f), ".conf")
		for _, m := range re.FindAllSubmatch(data, -1) {
			refs[string(m[2])] = append(refs[string(m[2])], vmid)
		}
	}
	for name, ids := range refs {
		sort.Strings(ids)
		refs[name] = compact(ids)
	}
	return refs, nil
}

// DefaultAt is the default daily sync time.
const DefaultAt = "04:30"

// SystemdUnits returns cerberus.service and cerberus.timer for running
// `<bin> sync --quiet` daily at at (HH:MM). The service is Type=oneshot,
// with Nice=10, IOSchedulingClass=idle, and After/Wants
// network-online.target. The timer has OnCalendar=*-*-* <at>,
// RandomizedDelaySec=1h, Persistent=true, and WantedBy=timers.target.
func SystemdUnits(bin, at string) (service, timer string) {
	service = "[Unit]\n" +
		"Description=cerberus ISO library sync\n" +
		"After=network-online.target\n" +
		"Wants=network-online.target\n\n" +
		"[Service]\n" +
		"Type=oneshot\n" +
		"Nice=10\n" +
		"IOSchedulingClass=idle\n" +
		"ExecStart=" + bin + " sync --quiet\n"
	timer = "[Unit]\n" +
		"Description=Daily cerberus ISO library sync\n\n" +
		"[Timer]\n" +
		"OnCalendar=*-*-* " + at + "\n" +
		"RandomizedDelaySec=1h\n" +
		"Persistent=true\n\n" +
		"[Install]\n" +
		"WantedBy=timers.target\n"
	return service, timer
}

// CronLine returns the /etc/cron.d/cerberus line for the same job.
func CronLine(bin, at string) string {
	h, m, _ := strings.Cut(at, ":")
	return fmt.Sprintf("%s %s * * * root %s sync --quiet", m, h, bin)
}

// InstallSchedule installs the daily job and returns a sentence describing
// what it did.
//   - With systemd: write the units to <root>/etc/systemd/system, then run
//     `systemctl daemon-reload` and `systemctl enable --now cerberus.timer`.
//   - Without systemd but with cron.d: write <root>/etc/cron.d/cerberus.
//   - Otherwise: change nothing and return the cron line to add by hand.
//
// It validates at as HH:MM first.
func InstallSchedule(ctx context.Context, root string, run Runner, info *Info, bin, at string) (string, error) {
	if !atRE.MatchString(at) {
		return "", fmt.Errorf("schedule time %q is not HH:MM (00:00 to 23:59)", at)
	}
	switch {
	case info.Systemd:
		dir := filepath.Join(root, "etc/systemd/system")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return "", err
		}
		service, timer := SystemdUnits(bin, at)
		for name, content := range map[string]string{"cerberus.service": service, "cerberus.timer": timer} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				return "", err
			}
		}
		if _, err := run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return "", err
		}
		if _, err := run.Run(ctx, "systemctl", "enable", "--now", "cerberus.timer"); err != nil {
			return "", err
		}
		return fmt.Sprintf("Installed cerberus.timer: daily at %s, plus up to an hour of random delay.", at), nil
	case info.CronD:
		dir := filepath.Join(root, "etc/cron.d")
		if err := os.WriteFile(filepath.Join(dir, "cerberus"), []byte("# cerberus\n"+CronLine(bin, at)+"\n"), 0o644); err != nil {
			return "", err
		}
		return fmt.Sprintf("Installed /etc/cron.d/cerberus: daily at %s.", at), nil
	}
	return "This host has neither systemd nor /etc/cron.d, so nothing was installed. To schedule cerberus, add this line to root's cron: " + CronLine(bin, at), nil
}

// RemoveSchedule undoes InstallSchedule. Removing what isn't there is not
// an error.
func RemoveSchedule(ctx context.Context, root string, run Runner, info *Info) (string, error) {
	switch {
	case info.Systemd:
		if _, err := run.Run(ctx, "systemctl", "disable", "--now", "cerberus.timer"); err != nil && !unitMissing(err) {
			return "", err
		}
		removed := false
		for _, name := range []string{"cerberus.timer", "cerberus.service"} {
			err := os.Remove(filepath.Join(root, "etc/systemd/system", name))
			if err == nil {
				removed = true
			} else if !errors.Is(err, fs.ErrNotExist) {
				return "", err
			}
		}
		if !removed {
			return "cerberus.timer was not installed.", nil
		}
		if _, err := run.Run(ctx, "systemctl", "daemon-reload"); err != nil {
			return "", err
		}
		return "Removed cerberus.timer and cerberus.service.", nil
	case info.CronD:
		err := os.Remove(filepath.Join(root, "etc/cron.d/cerberus"))
		if errors.Is(err, fs.ErrNotExist) {
			return "/etc/cron.d/cerberus was not installed.", nil
		}
		if err != nil {
			return "", err
		}
		return "Removed /etc/cron.d/cerberus.", nil
	}
	return "Nothing to remove: this host has neither systemd nor /etc/cron.d.", nil
}

// ScheduleStatus returns one line: the next run from `systemctl
// list-timers cerberus.timer --no-legend`, the cron.d line, or "not
// scheduled".
func ScheduleStatus(ctx context.Context, root string, run Runner, info *Info) (string, error) {
	switch {
	case info.Systemd:
		out, err := run.Run(ctx, "systemctl", "list-timers", "cerberus.timer", "--no-legend", "--all")
		if err != nil {
			return "", err
		}
		line := strings.TrimSpace(string(out))
		if line == "" {
			return "not scheduled", nil
		}
		line, _, _ = strings.Cut(line, "\n")
		if strings.HasPrefix(line, "n/a") {
			return "scheduled, but no next run", nil
		}
		if next := nextRE.FindString(line); next != "" {
			return "next run " + next, nil
		}
		return "scheduled", nil
	case info.CronD:
		data, err := os.ReadFile(filepath.Join(root, "etc/cron.d/cerberus"))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return "not scheduled", nil
			}
			return "", err
		}
		if m := cronRE.FindSubmatch(data); m != nil {
			mm, _ := strconv.Atoi(string(m[1]))
			hh, _ := strconv.Atoi(string(m[2]))
			return fmt.Sprintf("daily at %02d:%02d (cron)", hh, mm), nil
		}
	}
	return "not scheduled", nil
}

var (
	pveVersionRE = regexp.MustCompile(`pve-manager/([^/\s]+)`)
	atRE         = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)
	nextRE       = regexp.MustCompile(`^\S+ \d{4}-\d\d-\d\d \d\d:\d\d:\d\d \S+`)
	cronRE       = regexp.MustCompile(`(?m)^(\d+) (\d+) \* \* \* root `)
)

// num decodes a JSON number that PVE may also send as a bool or a string.
type num float64

func (n *num) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	switch s {
	case "null", "", "false":
		*n = 0
	case "true":
		*n = 1
	default:
		f, err := strconv.ParseFloat(s, 64)
		if err != nil {
			return fmt.Errorf("not a number: %s", b)
		}
		*n = num(f)
	}
	return nil
}

func unitMissing(err error) bool {
	m := err.Error()
	return strings.Contains(m, "does not exist") || strings.Contains(m, "not found") || strings.Contains(m, "not loaded")
}

func compact(s []string) []string {
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func isDir(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

func readTrim(p string) string {
	b, _ := os.ReadFile(p)
	return strings.TrimSpace(string(b))
}

func hostname() string {
	h, _ := os.Hostname()
	h, _, _ = strings.Cut(h, ".")
	return h
}

func osName(root string) string {
	for _, line := range strings.Split(readTrim(filepath.Join(root, "etc/os-release")), "\n") {
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			if v = strings.Trim(strings.TrimSpace(v), `"'`); v != "" {
				return v
			}
		}
	}
	return "Linux"
}

func sambaShares(root string) []Share {
	data, err := os.ReadFile(filepath.Join(root, "etc/samba/smb.conf"))
	if err != nil {
		return nil
	}
	type section struct {
		name string
		kv   map[string]string
	}
	var secs []*section
	var cur *section
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			name, _, ok := strings.Cut(line[1:], "]")
			if !ok {
				cur = nil
				continue
			}
			cur = &section{name: strings.TrimSpace(name), kv: map[string]string{}}
			secs = append(secs, cur)
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && cur != nil {
			cur.kv[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	var shares []Share
	for _, sec := range secs {
		switch strings.ToLower(sec.name) {
		case "global", "homes", "printers", "print$":
			continue
		}
		switch strings.ToLower(sec.kv["printable"]) {
		case "yes", "true", "1":
			continue
		}
		if p := sec.kv["path"]; p != "" {
			shares = append(shares, Share{Name: sec.name, Path: p, Proto: "smb"})
		}
	}
	return shares
}

func nfsShares(root string) []Share {
	data, err := os.ReadFile(filepath.Join(root, "etc/exports"))
	if err != nil {
		return nil
	}
	var shares []Share
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' {
			continue
		}
		var p string
		if line[0] == '"' {
			p, _, _ = strings.Cut(line[1:], `"`)
		} else {
			p = strings.Fields(line)[0]
		}
		if p != "" {
			shares = append(shares, Share{Name: p, Path: p, Proto: "nfs"})
		}
	}
	return shares
}
