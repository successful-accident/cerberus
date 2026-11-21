package library

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func pruneFixture(t *testing.T) (Layout, *EntryState) {
	l := Layout{Mode: ModeDir, Root: t.TempDir()}
	es := &EntryState{}
	for i, v := range []string{"3", "2", "1"} {
		rel := l.Rel("d", "d-"+v+".iso")
		write(t, l.Abs(rel), v)
		es.Files = append(es.Files, recOf(rel, v, i))
	}
	return l, es
}

func TestPrune(t *testing.T) {
	t.Run("keep 1", func(t *testing.T) {
		l, es := pruneFixture(t)
		removed, err := Prune(l, es, 1, nil)
		if err != nil || len(removed) != 2 || len(es.Files) != 1 || es.Files[0].Rel != "d/d-3.iso" {
			t.Fatalf("removed=%v files=%v err=%v", removed, es.Files, err)
		}
		if exists(l.Abs("d/d-2.iso")) || exists(l.Abs("d/d-1.iso")) || !exists(l.Abs("d/d-3.iso")) {
			t.Fatal("wrong files on disk")
		}
	})
	t.Run("keep 2", func(t *testing.T) {
		l, es := pruneFixture(t)
		removed, err := Prune(l, es, 2, nil)
		if err != nil || len(removed) != 1 || removed[0].Rel != "d/d-1.iso" || len(es.Files) != 2 {
			t.Fatalf("removed=%v err=%v", removed, err)
		}
		if !exists(l.Abs("d/d-2.iso")) || exists(l.Abs("d/d-1.iso")) {
			t.Fatal("wrong files on disk")
		}
	})
	t.Run("keep below 1 is 1, and enough files is a no-op", func(t *testing.T) {
		l, es := pruneFixture(t)
		es.Kept = []KeptNote{{Rel: "stale"}}
		if removed, err := Prune(l, es, 0, nil); err != nil || len(removed) != 2 || len(es.Files) != 1 {
			t.Fatalf("removed=%v err=%v", removed, err)
		}
		if es.Kept != nil {
			t.Fatal("Kept not reset")
		}
		if removed, err := Prune(l, es, 5, nil); err != nil || removed != nil || len(es.Files) != 1 {
			t.Fatalf("removed=%v err=%v", removed, err)
		}
	})
	t.Run("protected file stays with a note", func(t *testing.T) {
		l, es := pruneFixture(t)
		protect := func(rel string) string {
			if rel == "d/d-2.iso" {
				return "in use by VM 105"
			}
			return ""
		}
		removed, err := Prune(l, es, 1, protect)
		if err != nil || len(removed) != 1 || removed[0].Rel != "d/d-1.iso" {
			t.Fatalf("removed=%v err=%v", removed, err)
		}
		if len(es.Files) != 2 || es.Files[1].Rel != "d/d-2.iso" || !exists(l.Abs("d/d-2.iso")) {
			t.Fatalf("protected file lost: %v", es.Files)
		}
		if len(es.Kept) != 1 || es.Kept[0] != (KeptNote{Rel: "d/d-2.iso", Reason: "in use by VM 105"}) {
			t.Fatalf("kept=%v", es.Kept)
		}
	})
	t.Run("adopted file is dropped from state and stays on disk", func(t *testing.T) {
		l, es := pruneFixture(t)
		es.Files[1].Adopted = true
		removed, err := Prune(l, es, 1, nil)
		if err != nil || len(removed) != 1 || removed[0].Rel != "d/d-1.iso" {
			t.Fatalf("removed=%v err=%v", removed, err)
		}
		if len(es.Files) != 1 || !exists(l.Abs("d/d-2.iso")) {
			t.Fatal("adopted file must stay on disk, out of state")
		}
	})
	t.Run("already missing counts as deleted", func(t *testing.T) {
		l, es := pruneFixture(t)
		os.Remove(l.Abs("d/d-2.iso"))
		removed, err := Prune(l, es, 1, nil)
		if err != nil || len(removed) != 2 || len(es.Files) != 1 {
			t.Fatalf("removed=%v err=%v", removed, err)
		}
	})
	t.Run("a real error stops and keeps state honest", func(t *testing.T) {
		if os.Geteuid() == 0 {
			// Root ignores permissions, so make the delete fail another way:
			// a non-empty directory where the file should be.
			l, es := pruneFixture(t)
			os.Remove(l.Abs("d/d-1.iso"))
			write(t, l.Abs("d/d-1.iso/inner"), "x")
			removed, err := Prune(l, es, 1, nil)
			if err == nil || len(removed) != 1 || removed[0].Rel != "d/d-2.iso" {
				t.Fatalf("removed=%v err=%v", removed, err)
			}
			if len(es.Files) != 2 || es.Files[1].Rel != "d/d-1.iso" {
				t.Fatalf("files=%v", es.Files)
			}
			return
		}
		l, es := pruneFixture(t)
		if err := os.Chmod(filepath.Dir(l.Abs("d/d-1.iso")), 0o555); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { os.Chmod(filepath.Dir(l.Abs("d/d-1.iso")), 0o755) })
		removed, err := Prune(l, es, 1, nil)
		if err == nil || len(removed) != 0 || len(es.Files) != 3 {
			t.Fatalf("removed=%v files=%v err=%v", removed, es.Files, err)
		}
	})
	t.Run("a path outside the library is refused", func(t *testing.T) {
		l, es := pruneFixture(t)
		outside := filepath.Join(filepath.Dir(l.Root), "outside-"+filepath.Base(l.Root))
		write(t, outside, "x")
		es.Files[1].Rel = "../" + filepath.Base(outside)
		_, err := Prune(l, es, 1, nil)
		if err == nil || !strings.Contains(err.Error(), "not a path inside") || !exists(outside) {
			t.Fatalf("err=%v", err)
		}
	})
}

func reconcileFixture(t *testing.T) (Layout, *State, *Pending) {
	l := Layout{Mode: ModeDir, Root: t.TempDir()}
	s := &State{Schema: 1, Mode: ModeDir, Root: l.Root, Entries: map[string]*EntryState{}}
	s.Entry("d").Files = []FileRecord{recOf("d/old.iso", "old", 5)}
	rec := recOf("d/new.iso", "new bytes", 0)
	p := &Pending{Entry: "d", Part: "d/new.iso.part", File: rec}
	s.Pending = p
	return l, s, p
}

func all(string) bool { return true }

func TestReconcilePending(t *testing.T) {
	t.Run("finished when dst matches", func(t *testing.T) {
		l, s, _ := reconcileFixture(t)
		write(t, l.Abs("d/new.iso"), "new bytes")
		notes, err := Reconcile(l, s, all)
		if err != nil || len(notes) != 1 || s.Pending != nil {
			t.Fatalf("notes=%v err=%v pending=%v", notes, err, s.Pending)
		}
		files := s.Entries["d"].Files
		if len(files) != 2 || files[0].Rel != "d/new.iso" || files[0].Adopted {
			t.Fatalf("files=%+v", files)
		}
	})
	t.Run("not added twice", func(t *testing.T) {
		l, s, p := reconcileFixture(t)
		write(t, l.Abs("d/new.iso"), "new bytes")
		s.Entries["d"].Files = append([]FileRecord{p.File}, s.Entries["d"].Files...)
		if _, err := Reconcile(l, s, all); err != nil || len(s.Entries["d"].Files) != 2 {
			t.Fatalf("err=%v files=%v", err, s.Entries["d"].Files)
		}
	})
	t.Run("part still there means dst was already present: adopted, part removed", func(t *testing.T) {
		l, s, _ := reconcileFixture(t)
		write(t, l.Abs("d/new.iso"), "new bytes")
		write(t, l.Abs("d/new.iso.part"), "new bytes")
		if _, err := Reconcile(l, s, all); err != nil {
			t.Fatal(err)
		}
		if exists(l.Abs("d/new.iso.part")) || !exists(l.Abs("d/new.iso")) {
			t.Fatal("part should go, dst stay")
		}
		if !s.Entries["d"].Files[0].Adopted {
			t.Fatal("record should be adopted")
		}
	})
	t.Run("rolled back when dst is missing, part kept as a partial", func(t *testing.T) {
		l, s, _ := reconcileFixture(t)
		write(t, l.Abs("d/new.iso.part"), "new bytes")
		notes, err := Reconcile(l, s, all)
		if err != nil || len(notes) != 1 || s.Pending != nil {
			t.Fatalf("notes=%v err=%v", notes, err)
		}
		if len(s.Entries["d"].Files) != 1 {
			t.Fatal("record must not be added")
		}
		if pt, ok := s.Partials["d/new.iso.part"]; !ok || pt.Entry != "d" || pt.Version != "d/new.iso" {
			t.Fatalf("partials=%v", s.Partials)
		}
		if !exists(l.Abs("d/new.iso.part")) {
			t.Fatal("part must stay")
		}
	})
	t.Run("rolled back with no part leaves no partial", func(t *testing.T) {
		l, s, _ := reconcileFixture(t)
		if _, err := Reconcile(l, s, all); err != nil || len(s.Partials) != 0 || s.Pending != nil {
			t.Fatalf("err=%v partials=%v", err, s.Partials)
		}
	})
	t.Run("a different file at dst is not ours: rolled back, dst untouched", func(t *testing.T) {
		l, s, _ := reconcileFixture(t)
		write(t, l.Abs("d/new.iso"), "something else")
		write(t, l.Abs("d/new.iso.part"), "new bytes")
		if _, err := Reconcile(l, s, all); err != nil {
			t.Fatal(err)
		}
		if read(t, l.Abs("d/new.iso")) != "something else" || len(s.Entries["d"].Files) != 1 || len(s.Partials) != 1 {
			t.Fatal("wrong outcome")
		}
	})
}

func TestReconcilePartials(t *testing.T) {
	l := Layout{Mode: ModeDir, Root: t.TempDir()}
	s := &State{Schema: 1, Entries: map[string]*EntryState{}, Partials: map[string]Partial{
		"gone/g.iso.part": {Entry: "gone", Version: "1"},
		"kept/k.iso.part": {Entry: "kept", Version: "1"},
	}}
	write(t, l.Abs("gone/g.iso.part"), "g")
	write(t, l.Abs("gone/g.iso.part.meta"), "m")
	write(t, l.Abs("kept/k.iso.part"), "k")
	write(t, l.Abs("kept/k.iso.part.meta"), "m")
	write(t, l.Abs("gone/stranger.iso.part"), "not ours")
	write(t, l.Abs("other.iso.part"), "not ours")

	notes, err := Reconcile(l, s, func(id string) bool { return id == "kept" })
	if err != nil || len(notes) != 1 {
		t.Fatalf("notes=%v err=%v", notes, err)
	}
	if exists(l.Abs("gone/g.iso.part")) || exists(l.Abs("gone/g.iso.part.meta")) {
		t.Fatal("unselected partial not deleted")
	}
	for _, p := range []string{"kept/k.iso.part", "kept/k.iso.part.meta", "gone/stranger.iso.part", "other.iso.part"} {
		if !exists(l.Abs(p)) {
			t.Fatalf("%s must not be deleted", p)
		}
	}
	if _, ok := s.Partials["gone/g.iso.part"]; ok || len(s.Partials) != 1 {
		t.Fatalf("partials=%v", s.Partials)
	}
}

// A crash after Place adopts a hand-uploaded file, but before the caller
// saves the adoption, must not make the user's file look like cerberus's.
func TestCrashAfterAdoptionNeverPrunesUserFile(t *testing.T) {
	l := Layout{Mode: ModeDir, Root: t.TempDir()}
	rel := "deb/x-2.0.iso"
	write(t, l.Abs(rel), "iso 2.0")         // the user's own upload
	write(t, l.Abs(rel)+".part", "iso 2.0") // cerberus's verified download
	rec := recOf(rel, "iso 2.0", 0)
	s := &State{Schema: 1, Entries: map[string]*EntryState{"deb": {}},
		Pending: &Pending{Entry: "deb", Part: rel + ".part", File: rec}} // journal saved by the engine

	adopted, err := Place(l.Abs(rel)+".part", l.Abs(rel), rec.Checksum())
	if err != nil || !adopted {
		t.Fatalf("Place: adopted=%v err=%v", adopted, err)
	}
	// The process dies here, before the engine records Adopted and saves.

	if _, err := Reconcile(l, s, all); err != nil {
		t.Fatal(err)
	}
	if exists(l.Abs(rel) + ".part") {
		t.Error("Reconcile should remove the part file the adoption left")
	}
	newer := recOf("deb/x-3.0.iso", "iso 3.0", -24)
	write(t, l.Abs(newer.Rel), "iso 3.0")
	es := s.Entries["deb"]
	es.Files = append([]FileRecord{newer}, es.Files...)
	if _, err := Prune(l, es, 1, nil); err != nil {
		t.Fatal(err)
	}
	if !exists(l.Abs(rel)) {
		t.Fatalf("prune deleted %s, the user's own upload", rel)
	}
}
