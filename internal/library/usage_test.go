package library

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func usageState(l Layout) *State {
	s := &State{Schema: 1, Entries: map[string]*EntryState{}}
	s.Entry("d").Files = []FileRecord{
		recOf(l.Rel("d", "d-2.iso"), strings.Repeat("x", 100), 0),
		recOf(l.Rel("d", "d-1.iso"), strings.Repeat("x", 50), 1), // missing on disk
	}
	s.Partials = map[string]Partial{l.Rel("d", "d-3.iso.part"): {Entry: "d"}}
	s.Pending = &Pending{Entry: "d", Part: l.Rel("d", "d-4.iso.part")}
	return s
}

func TestDiskUsageDirMode(t *testing.T) {
	l := Layout{Mode: ModeDir, Root: t.TempDir(), Aliases: true}
	s := usageState(l)
	write(t, l.Abs("d/d-2.iso"), strings.Repeat("x", 100))
	write(t, l.Abs("d/d-3.iso.part"), "12345")      // known partial
	write(t, l.Abs("d/d-3.iso.part.meta"), "12345") // its meta
	write(t, l.Abs("d/d-4.iso.part"), "12345")      // pending part
	write(t, l.Abs("d/stranger.iso.part"), "1234567")
	write(t, l.Abs("d/notes.txt"), "123")
	write(t, l.Abs("other/deep/file.bin"), "1234567890")
	write(t, filepath.Join(l.Root, OwnerFile), "host")
	if err := SetAlias(l, "d", "d/d-2.iso"); err != nil {
		t.Fatal(err)
	}
	write(t, l.Abs("latest/readme"), "should be skipped with latest/")

	u, err := DiskUsage(l, s)
	if err != nil {
		t.Fatal(err)
	}
	if u.Managed != 100 {
		t.Fatalf("managed=%d", u.Managed)
	}
	if want := int64(7 + 3 + 10); u.Other != want {
		t.Fatalf("other=%d, want %d", u.Other, want)
	}
	if u.Total == 0 || u.Avail == 0 || u.Avail > u.Total {
		t.Fatalf("avail=%d total=%d", u.Avail, u.Total)
	}
}

func TestDiskUsagePVEMode(t *testing.T) {
	l := Layout{Mode: ModePVE, Root: t.TempDir()}
	s := &State{Schema: 1, Entries: map[string]*EntryState{}}
	s.Entry("d").Files = []FileRecord{recOf("d-2.iso", strings.Repeat("x", 100), 0)}
	s.Partials = map[string]Partial{"d-3.iso.part": {Entry: "d"}}
	write(t, l.Abs("d-2.iso"), strings.Repeat("x", 100))
	write(t, l.Abs("d-3.iso.part"), "12345")
	write(t, l.Abs("hand-uploaded.iso"), "123456")
	write(t, l.Abs("sub/ignored.iso"), "must not be counted: no recursion")
	write(t, filepath.Join(l.Root, OwnerFile), "host")
	if err := os.Symlink("d-2.iso", l.Abs("link.iso")); err != nil {
		t.Fatal(err)
	}

	u, err := DiskUsage(l, s)
	if err != nil {
		t.Fatal(err)
	}
	if u.Managed != 100 || u.Other != 6 {
		t.Fatalf("managed=%d other=%d", u.Managed, u.Other)
	}
}

func TestDiskUsageMissingRoot(t *testing.T) {
	l := Layout{Mode: ModeDir, Root: filepath.Join(t.TempDir(), "nope")}
	if _, err := DiskUsage(l, &State{}); err == nil {
		t.Fatal("want an error")
	}
}
