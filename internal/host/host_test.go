package host

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

type fakeRun struct {
	out   map[string]string // command line -> stdout
	fail  map[string]string // command line -> error text
	calls []string
}

func (f *fakeRun) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	line := strings.Join(append([]string{name}, args...), " ")
	f.calls = append(f.calls, line)
	if msg, ok := f.fail[line]; ok {
		return nil, errors.New(msg)
	}
	return []byte(f.out[line]), nil
}

func write(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

const debianOS = "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\n"

func TestExecRunner(t *testing.T) {
	out, err := ExecRunner{}.Run(context.Background(), "sh", "-c", "echo out; echo err >&2")
	if err != nil || string(out) != "out\n" {
		t.Fatalf("got %q, %v", out, err)
	}
	_, err = ExecRunner{}.Run(context.Background(), "sh", "-c", "echo boom >&2; exit 3")
	if err == nil || !strings.Contains(err.Error(), "sh -c echo boom >&2; exit 3: exit status 3: boom") {
		t.Errorf("got %v", err)
	}
}

func TestDetectPVE(t *testing.T) {
	root := t.TempDir()
	write(t, root, "usr/bin/pvesh", "")
	write(t, root, "etc/machine-id", "abc123\n")
	write(t, root, "etc/os-release", debianOS)
	write(t, root, "etc/samba/smb.conf", "[data]\npath=/x\n") // PVE wins
	if err := os.MkdirAll(filepath.Join(root, "etc/pve/nodes/pve1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("nodes/pve1", filepath.Join(root, "etc/pve/local")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		out  map[string]string
		fail map[string]string
		name string
	}{
		{map[string]string{"pveversion": "pve-manager/9.2.1/abcdef01 (running kernel: 6.14.8-2-pve)\n"}, nil, "Proxmox VE 9.2.1"},
		{nil, map[string]string{"pveversion": "no such command"}, "Proxmox VE"},
	} {
		info, err := Detect(context.Background(), root, &fakeRun{out: tc.out, fail: tc.fail})
		if err != nil {
			t.Fatal(err)
		}
		if info.Kind != KindPVE || info.Node != "pve1" || info.Name != tc.name || info.MachineID != "abc123" {
			t.Errorf("got %+v", info)
		}
		if !reflect.DeepEqual(info.Suggestions, []string{"/srv/isos"}) || len(info.Shares) != 0 {
			t.Errorf("suggestions/shares: %+v", info)
		}
		if info.Hostname == "" || strings.Contains(info.Hostname, ".") {
			t.Errorf("hostname %q", info.Hostname)
		}
		if info.Root != (os.Geteuid() == 0) {
			t.Error("Root mismatch")
		}
	}
}

func TestDetectPVENeedsPvesh(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "etc/pve"), 0o755)
	info, _ := Detect(context.Background(), root, &fakeRun{})
	if info.Kind != KindLinux {
		t.Errorf("got %v", info.Kind)
	}
}

func TestDetectFileServer(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/os-release", debianOS)
	write(t, root, "etc/samba/smb.conf", `# comment
; comment
[global]
   workgroup = WG
   path = /ignored

[homes]
   path = /home

[printers]
   path = /var/spool/samba

[print$]
   path = /var/lib/samba/printers

[Laser]
   path = /srv/laser
   Printable = Yes

[media]
   Path = /srv/media
   read only = no

[backup]
   path=/srv/backup
   printable = no

[empty]
   comment = no path
`)
	write(t, root, "etc/exports", "# nfs\n\n/srv/nfs1 10.0.0.0/24(rw)\n\"/srv/my nfs\" *(ro)\n")
	write(t, root, "etc/machine-id", "m1\n")
	write(t, root, "run/systemd/system/.keep", "")
	write(t, root, "etc/cron.d/.keep", "")
	info, err := Detect(context.Background(), root, &fakeRun{})
	if err != nil {
		t.Fatal(err)
	}
	wantShares := []Share{
		{"media", "/srv/media", "smb"},
		{"backup", "/srv/backup", "smb"},
		{"/srv/nfs1", "/srv/nfs1", "nfs"},
		{"/srv/my nfs", "/srv/my nfs", "nfs"},
	}
	if info.Kind != KindFileServer || !reflect.DeepEqual(info.Shares, wantShares) {
		t.Errorf("got %v %+v", info.Kind, info.Shares)
	}
	wantSug := []string{"/srv/media/isos", "/srv/backup/isos", "/srv/nfs1/isos", "/srv/my nfs/isos", "/srv/isos"}
	if !reflect.DeepEqual(info.Suggestions, wantSug) {
		t.Errorf("suggestions %v", info.Suggestions)
	}
	if info.Name != "Debian GNU/Linux 13 (trixie)" || !info.Systemd || !info.CronD {
		t.Errorf("got %+v", info)
	}
}

func TestDetectLinux(t *testing.T) {
	root := t.TempDir()
	info, err := Detect(context.Background(), root, &fakeRun{})
	if err != nil {
		t.Fatal(err)
	}
	if info.Kind != KindLinux || info.Name != "Linux" || info.Systemd || info.CronD || info.MachineID != "" {
		t.Errorf("empty root: %+v", info)
	}
	write(t, root, "etc/os-release", debianOS)
	write(t, root, "etc/samba/smb.conf", "[global]\n[homes]\npath=/h\n")
	info, _ = Detect(context.Background(), root, &fakeRun{})
	if info.Kind != KindLinux || info.Name != "Debian GNU/Linux 13 (trixie)" || !reflect.DeepEqual(info.Suggestions, []string{"/srv/isos"}) {
		t.Errorf("got %+v", info)
	}
}

const pveshCmd = "pvesh get /nodes/pve1/storage --content iso --enabled 1 --output-format json"

const pveshJSON = `[{"active":1,"avail":81085388800,"content":"iso,vztmpl,backup,snippets","enabled":1,"shared":0,"storage":"local","total":100861726720,"type":"dir","used":14632755200,"used_fraction":0.145},{"active":0,"content":"iso","enabled":1,"shared":1,"storage":"nas-iso","type":"nfs"},{"content":"iso","storage":"bare","type":"dir"}]`

func TestPVEStorages(t *testing.T) {
	run := &fakeRun{out: map[string]string{pveshCmd: pveshJSON}}
	got, err := PVEStorages(context.Background(), run, "pve1")
	if err != nil {
		t.Fatal(err)
	}
	want := []Storage{
		{ID: "local", Type: "dir", Content: "iso,vztmpl,backup,snippets", Active: true, Enabled: true, Total: 100861726720, Used: 14632755200, Avail: 81085388800},
		{ID: "nas-iso", Type: "nfs", Content: "iso", Enabled: true, Shared: true},
		{ID: "bare", Type: "dir", Content: "iso"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v", got)
	}
	for _, bad := range []string{"not json", `{"a":1}`} {
		run.out[pveshCmd] = bad
		if _, err := PVEStorages(context.Background(), run, "pve1"); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
	run = &fakeRun{fail: map[string]string{pveshCmd: "pvesh: exit 1"}}
	if _, err := PVEStorages(context.Background(), run, "pve1"); err == nil {
		t.Error("want runner error")
	}
}

func TestPVEStorageReady(t *testing.T) {
	run := &fakeRun{out: map[string]string{pveshCmd: pveshJSON}}
	st, err := PVEStorageReady(context.Background(), run, "pve1", "local")
	if err != nil || st.ID != "local" || st.Avail != 81085388800 {
		t.Fatalf("got %+v, %v", st, err)
	}
	for _, tc := range []struct{ id, want string }{
		{"missing", "not enabled for ISOs on node"},
		{"bare", "not enabled for ISOs on node"},
		{"nas-iso", "not active"},
	} {
		st, err := PVEStorageReady(context.Background(), run, "pve1", tc.id)
		if st != nil || err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %+v, %v", tc.id, st, err)
		}
	}
	if err := func() error {
		_, err := PVEStorageReady(context.Background(), run, "pve1", "nas-iso")
		return err
	}(); !strings.Contains(err.Error(), "unmounted") {
		t.Errorf("want unmounted hint: %v", err)
	}
}

func TestPVEISODir(t *testing.T) {
	cmd := "pvesm path local:iso/cerberus-probe.iso"
	run := &fakeRun{out: map[string]string{cmd: "/var/lib/vz/template/iso/cerberus-probe.iso\n"}}
	got, err := PVEISODir(context.Background(), run, "local")
	if err != nil || got != "/var/lib/vz/template/iso" {
		t.Errorf("got %q, %v", got, err)
	}
	run.out[cmd] = "relative/x.iso\n"
	if _, err := PVEISODir(context.Background(), run, "local"); err == nil {
		t.Error("relative path: want error")
	}
	run = &fakeRun{fail: map[string]string{cmd: "no such storage"}}
	if _, err := PVEISODir(context.Background(), run, "local"); err == nil {
		t.Error("want runner error")
	}
}

func TestVMISORefs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/pve/nodes/pve1/qemu-server/100.conf", `boot: order=ide2
ide2: local:iso/ubuntu-26.04.1-live-server-amd64.iso,media=cdrom,size=2G
ide3: none,media=cdrom
scsi0: local:100/vm-100-disk-0.raw

[before-upgrade]
ide2: local:iso/ubuntu-24.04-live-server-amd64.iso,media=cdrom
ide3: nas:iso/x.iso,media=cdrom
`)
	write(t, root, "etc/pve/nodes/pve2/qemu-server/105.conf", `ide2: local:iso/ubuntu-26.04.1-live-server-amd64.iso,media=cdrom
ide3: local-nfs:iso/y.iso,media=cdrom
ide0: local:iso/ubuntu-26.04.1-live-server-amd64.iso
`)
	write(t, root, "etc/pve/nodes/pve2/qemu-server/101.conf", "ide2: local:iso/ubuntu-26.04.1-live-server-amd64.iso,media=cdrom\n")
	write(t, root, "etc/pve/nodes/pve2/qemu-server/notes.txt", "local:iso/ignored.iso\n")
	write(t, root, "etc/pve/nodes/pve2/lxc/200.conf", "local:iso/ignored2.iso\n")

	got, err := VMISORefs(root, "local")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{
		"ubuntu-26.04.1-live-server-amd64.iso": {"100", "101", "105"},
		"ubuntu-24.04-live-server-amd64.iso":   {"100"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("local: got %v", got)
	}
	got, _ = VMISORefs(root, "nas")
	if !reflect.DeepEqual(got, map[string][]string{"x.iso": {"100"}}) {
		t.Errorf("nas: got %v", got)
	}
	got, _ = VMISORefs(root, "local-nfs")
	if !reflect.DeepEqual(got, map[string][]string{"y.iso": {"105"}}) {
		t.Errorf("local-nfs: got %v", got)
	}
	// No cluster folder at all is not an error.
	if got, err := VMISORefs(t.TempDir(), "local"); err != nil || len(got) != 0 {
		t.Errorf("empty: got %v, %v", got, err)
	}
}

func TestUnitsAndCronLine(t *testing.T) {
	svc, tmr := SystemdUnits("/usr/local/bin/cerberus", "04:30")
	for _, want := range []string{"Type=oneshot", "Nice=10", "IOSchedulingClass=idle", "After=network-online.target", "Wants=network-online.target", "ExecStart=/usr/local/bin/cerberus sync --quiet"} {
		if !strings.Contains(svc, want) {
			t.Errorf("service lacks %q", want)
		}
	}
	for _, want := range []string{"OnCalendar=*-*-* 04:30", "RandomizedDelaySec=1h", "Persistent=true", "WantedBy=timers.target"} {
		if !strings.Contains(tmr, want) {
			t.Errorf("timer lacks %q", want)
		}
	}
	if got, want := CronLine("/usr/local/bin/cerberus", "04:30"), "30 04 * * * root /usr/local/bin/cerberus sync --quiet"; got != want {
		t.Errorf("got %q", got)
	}
}

func TestSystemdUnitsVerify(t *testing.T) {
	if _, err := exec.LookPath("systemd-analyze"); err != nil {
		t.Skip("systemd-analyze not available")
	}
	dir := t.TempDir()
	svc, tmr := SystemdUnits("/bin/true", "04:30")
	os.WriteFile(filepath.Join(dir, "cerberus.service"), []byte(svc), 0o644)
	os.WriteFile(filepath.Join(dir, "cerberus.timer"), []byte(tmr), 0o644)
	out, err := exec.Command("systemd-analyze", "verify", filepath.Join(dir, "cerberus.service"), filepath.Join(dir, "cerberus.timer")).CombinedOutput()
	if err != nil {
		t.Errorf("systemd-analyze verify: %v\n%s", err, out)
	}
}

func TestInstallSchedule(t *testing.T) {
	ctx := context.Background()
	const bin = "/usr/local/bin/cerberus"

	t.Run("systemd", func(t *testing.T) {
		root := t.TempDir()
		run := &fakeRun{}
		msg, err := InstallSchedule(ctx, root, run, &Info{Systemd: true, CronD: true}, bin, "04:30")
		if err != nil {
			t.Fatal(err)
		}
		if msg != "Installed cerberus.timer: daily at 04:30, plus up to an hour of random delay." {
			t.Errorf("msg %q", msg)
		}
		svc, tmr := SystemdUnits(bin, "04:30")
		for name, want := range map[string]string{"cerberus.service": svc, "cerberus.timer": tmr} {
			p := filepath.Join(root, "etc/systemd/system", name)
			b, err := os.ReadFile(p)
			fi, _ := os.Stat(p)
			if err != nil || string(b) != want || fi.Mode().Perm() != 0o644 {
				t.Errorf("%s: %v %v", name, err, fi)
			}
		}
		if want := []string{"systemctl daemon-reload", "systemctl enable --now cerberus.timer"}; !reflect.DeepEqual(run.calls, want) {
			t.Errorf("calls %v", run.calls)
		}
		if exists(filepath.Join(root, "etc/cron.d/cerberus")) {
			t.Error("cron file written alongside systemd")
		}
	})

	t.Run("crond", func(t *testing.T) {
		root := t.TempDir()
		os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0o755)
		run := &fakeRun{}
		msg, err := InstallSchedule(ctx, root, run, &Info{CronD: true}, bin, "23:05")
		if err != nil || !strings.Contains(msg, "23:05") {
			t.Fatalf("%q, %v", msg, err)
		}
		b, _ := os.ReadFile(filepath.Join(root, "etc/cron.d/cerberus"))
		if want := "# cerberus\n05 23 * * * root " + bin + " sync --quiet\n"; string(b) != want {
			t.Errorf("got %q", b)
		}
		if len(run.calls) != 0 {
			t.Errorf("calls %v", run.calls)
		}
	})

	t.Run("neither", func(t *testing.T) {
		root := t.TempDir()
		msg, err := InstallSchedule(ctx, root, &fakeRun{}, &Info{}, bin, "04:30")
		if err != nil || !strings.Contains(msg, CronLine(bin, "04:30")) {
			t.Errorf("%q, %v", msg, err)
		}
		if ents, _ := os.ReadDir(root); len(ents) != 0 {
			t.Errorf("wrote %v", ents)
		}
	})

	t.Run("bad time", func(t *testing.T) {
		for _, at := range []string{"", "4:30", "24:00", "12:60", "04:30 ", "ab:cd", "04:300"} {
			root := t.TempDir()
			run := &fakeRun{}
			if _, err := InstallSchedule(ctx, root, run, &Info{Systemd: true}, bin, at); err == nil {
				t.Errorf("%q: want error", at)
			}
			if len(run.calls) != 0 || exists(filepath.Join(root, "etc")) {
				t.Errorf("%q: side effects", at)
			}
		}
	})

	t.Run("systemctl failure", func(t *testing.T) {
		run := &fakeRun{fail: map[string]string{"systemctl enable --now cerberus.timer": "boom"}}
		if _, err := InstallSchedule(ctx, t.TempDir(), run, &Info{Systemd: true}, bin, "04:30"); err == nil {
			t.Error("want error")
		}
	})
}

func TestRemoveSchedule(t *testing.T) {
	ctx := context.Background()
	const disable = "systemctl disable --now cerberus.timer"

	t.Run("systemd", func(t *testing.T) {
		root := t.TempDir()
		info := &Info{Systemd: true}
		if _, err := InstallSchedule(ctx, root, &fakeRun{}, info, "/bin/cerberus", "04:30"); err != nil {
			t.Fatal(err)
		}
		run := &fakeRun{}
		msg, err := RemoveSchedule(ctx, root, run, info)
		if err != nil || !strings.Contains(msg, "Removed") {
			t.Fatalf("%q, %v", msg, err)
		}
		if want := []string{disable, "systemctl daemon-reload"}; !reflect.DeepEqual(run.calls, want) {
			t.Errorf("calls %v", run.calls)
		}
		for _, n := range []string{"cerberus.service", "cerberus.timer"} {
			if exists(filepath.Join(root, "etc/systemd/system", n)) {
				t.Errorf("%s remains", n)
			}
		}
	})

	t.Run("systemd, nothing installed", func(t *testing.T) {
		run := &fakeRun{fail: map[string]string{disable: "Failed to disable unit: Unit file cerberus.timer does not exist."}}
		msg, err := RemoveSchedule(ctx, t.TempDir(), run, &Info{Systemd: true})
		if err != nil || !strings.Contains(msg, "not installed") {
			t.Errorf("%q, %v", msg, err)
		}
	})

	t.Run("systemd, other failure", func(t *testing.T) {
		run := &fakeRun{fail: map[string]string{disable: "Failed to connect to bus"}}
		if _, err := RemoveSchedule(ctx, t.TempDir(), run, &Info{Systemd: true}); err == nil {
			t.Error("want error")
		}
	})

	t.Run("crond", func(t *testing.T) {
		root := t.TempDir()
		info := &Info{CronD: true}
		os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0o755)
		InstallSchedule(ctx, root, &fakeRun{}, info, "/bin/cerberus", "04:30")
		if msg, err := RemoveSchedule(ctx, root, &fakeRun{}, info); err != nil || !strings.Contains(msg, "Removed") {
			t.Fatalf("%q, %v", msg, err)
		}
		if exists(filepath.Join(root, "etc/cron.d/cerberus")) {
			t.Error("file remains")
		}
		if _, err := RemoveSchedule(ctx, root, &fakeRun{}, info); err != nil {
			t.Errorf("second removal: %v", err)
		}
	})

	t.Run("neither", func(t *testing.T) {
		if _, err := RemoveSchedule(ctx, t.TempDir(), &fakeRun{}, &Info{}); err != nil {
			t.Error(err)
		}
	})
}

func TestScheduleStatus(t *testing.T) {
	ctx := context.Background()
	const cmd = "systemctl list-timers cerberus.timer --no-legend --all"

	for _, tc := range []struct{ out, want string }{
		{"", "not scheduled"},
		{"\n", "not scheduled"},
		{"Fri 2026-11-21 04:47:12 UTC 3h 12min left Thu 2026-11-20 04:31:00 UTC 20h ago cerberus.timer cerberus.service\n", "next run Fri 2026-11-21 04:47:12 UTC"},
		{"n/a n/a Thu 2026-11-20 04:31:00 UTC 20h ago cerberus.timer cerberus.service\n", "scheduled, but no next run"},
	} {
		got, err := ScheduleStatus(ctx, t.TempDir(), &fakeRun{out: map[string]string{cmd: tc.out}}, &Info{Systemd: true})
		if err != nil || got != tc.want {
			t.Errorf("%q: got %q, %v", tc.out, got, err)
		}
	}
	if _, err := ScheduleStatus(ctx, t.TempDir(), &fakeRun{fail: map[string]string{cmd: "boom"}}, &Info{Systemd: true}); err == nil {
		t.Error("want error")
	}

	root := t.TempDir()
	info := &Info{CronD: true}
	os.MkdirAll(filepath.Join(root, "etc/cron.d"), 0o755)
	if got, _ := ScheduleStatus(ctx, root, &fakeRun{}, info); got != "not scheduled" {
		t.Errorf("cron, none: %q", got)
	}
	InstallSchedule(ctx, root, &fakeRun{}, info, "/bin/cerberus", "04:30")
	if got, _ := ScheduleStatus(ctx, root, &fakeRun{}, info); got != "daily at 04:30 (cron)" {
		t.Errorf("cron: %q", got)
	}
	if got, err := ScheduleStatus(ctx, t.TempDir(), &fakeRun{}, &Info{}); err != nil || got != "not scheduled" {
		t.Errorf("neither: %q, %v", got, err)
	}
}
