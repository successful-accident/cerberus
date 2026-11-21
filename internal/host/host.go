// Package host inspects the machine cerberus runs on: whether it's a
// Proxmox VE host, a file server, or plain Linux. It also covers PVE
// storages and the ISOs that VMs reference, and installs the schedule.
//
// Every function that reads the filesystem takes a root path, "/" in
// production, and every command runs through a Runner, so tests can use a
// fake host tree and fake commands.
package host

import (
	"context"
	"os/exec"
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
	panic("host.ExecRunner.Run: not implemented (phase 1)")
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
	panic("host.Detect: not implemented (phase 1)")
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
	panic("host.PVEStorages: not implemented (phase 1)")
}

// PVEStorageReady re-lists the node's storages and returns the named one
// only if it's enabled and active. Otherwise it returns an error that says
// which. Call it before every write: an unmounted NFS storage would
// otherwise send ISOs to the boot disk.
func PVEStorageReady(ctx context.Context, run Runner, node, storage string) (*Storage, error) {
	panic("host.PVEStorageReady: not implemented (phase 1)")
}

// PVEISODir returns the storage's ISO folder, the directory part of `pvesm
// path <storage>:iso/cerberus-probe.iso`. That honors content-dirs
// overrides and doesn't need the file to exist.
func PVEISODir(ctx context.Context, run Runner, storage string) (string, error) {
	panic("host.PVEISODir: not implemented (phase 1)")
}

// VMISORefs maps each ISO file name on the storage to the VM IDs whose
// config mentions <storage>:iso/<name>, in any section, snapshots included.
// It reads <root>/etc/pve/nodes/*/qemu-server/*.conf, covering every node in
// a cluster.
func VMISORefs(root, storage string) (map[string][]string, error) {
	panic("host.VMISORefs: not implemented (phase 1)")
}

// DefaultAt is the default daily sync time.
const DefaultAt = "04:30"

// SystemdUnits returns cerberus.service and cerberus.timer for running
// `<bin> sync --quiet` daily at at (HH:MM). The service is Type=oneshot,
// with Nice=10, IOSchedulingClass=idle, and After/Wants
// network-online.target. The timer has OnCalendar=*-*-* <at>,
// RandomizedDelaySec=1h, Persistent=true, and WantedBy=timers.target.
func SystemdUnits(bin, at string) (service, timer string) {
	panic("host.SystemdUnits: not implemented (phase 1)")
}

// CronLine returns the /etc/cron.d/cerberus line for the same job.
func CronLine(bin, at string) string {
	panic("host.CronLine: not implemented (phase 1)")
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
	panic("host.InstallSchedule: not implemented (phase 1)")
}

// RemoveSchedule undoes InstallSchedule. Removing what isn't there is not
// an error.
func RemoveSchedule(ctx context.Context, root string, run Runner, info *Info) (string, error) {
	panic("host.RemoveSchedule: not implemented (phase 1)")
}

// ScheduleStatus returns one line: the next run from `systemctl
// list-timers cerberus.timer --no-legend`, the cron.d line, or "not
// scheduled".
func ScheduleStatus(ctx context.Context, root string, run Runner, info *Info) (string, error) {
	panic("host.ScheduleStatus: not implemented (phase 1)")
}
