package library

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

type relocEnv struct {
	from, to  Layout
	s         *State
	statePath string
}

// newReloc builds a dir-mode library with entries a (two files) and b.
func newReloc(t *testing.T) *relocEnv {
	t.Helper()
	base := t.TempDir()
	e := &relocEnv{
		from:      Layout{Mode: ModeDir, Root: filepath.Join(base, "old")},
		to:        Layout{Mode: ModeDir, Root: filepath.Join(base, "new")},
		statePath: filepath.Join(base, "state.json"),
		s:         &State{Schema: 1, Entries: map[string]*EntryState{}},
	}
	e.s.Mode, e.s.Root = ModeDir, e.from.Root
	for id, files := range map[string][]string{"a": {"a-2.iso", "a-1.iso"}, "b": {"b-1.iso"}} {
		for i, f := range files {
			rel := e.from.Rel(id, f)
			write(t, e.from.Abs(rel), "content of "+f)
			es := e.s.Entry(id)
			es.Files = append(es.Files, recOf(rel, "content of "+f, i))
		}
	}
	return e
}

func (e *relocEnv) plan(t *testing.T, mode FileMode, protect ProtectFunc) {
	t.Helper()
	r, err := PlanRelocation(e.s, e.from, e.to, mode, protect)
	if err != nil {
		t.Fatal(err)
	}
	e.s.Relocation = r
}

func (e *relocEnv) save() error { return e.s.Save(e.statePath) }

func forceCopy(t *testing.T) {
	old := sameFS
	sameFS = func(a, b string) (bool, error) { return false, nil }
	t.Cleanup(func() { sameFS = old })
}

func actions(r *Relocation) []string {
	var out []string
	for _, it := range r.Items {
		out = append(out, it.Entry+":"+it.Action)
	}
	return out
}

func TestPlanActions(t *testing.T) {
	protect := func(rel string) string {
		if rel == "a/a-1.iso" {
			return "in use by VM 105"
		}
		return ""
	}
	t.Run("move, same filesystem", func(t *testing.T) {
		e := newReloc(t)
		e.plan(t, FilesMove, protect)
		got := strings.Join(actions(e.s.Relocation), " ")
		if got != "a:rename a:copy-keep b:rename" {
			t.Fatal(got)
		}
		if it := e.s.Relocation.Items[1]; it.Reason != "in use by VM 105" || it.ToRel != "a/a-1.iso" || it.FromRel != "a/a-1.iso" {
			t.Fatalf("%+v", it)
		}
	})
	t.Run("move, other filesystem", func(t *testing.T) {
		forceCopy(t)
		e := newReloc(t)
		e.plan(t, FilesMove, nil)
		if got := strings.Join(actions(e.s.Relocation), " "); got != "a:copy a:copy b:copy" {
			t.Fatal(got)
		}
	})
	t.Run("copy and leave", func(t *testing.T) {
		e := newReloc(t)
		e.plan(t, FilesCopy, nil)
		if got := strings.Join(actions(e.s.Relocation), " "); got != "a:copy-keep a:copy-keep b:copy-keep" {
			t.Fatal(got)
		}
		e.plan(t, FilesLeave, nil)
		if got := strings.Join(actions(e.s.Relocation), " "); got != "a:skip a:skip b:skip" {
			t.Fatal(got)
		}
	})
	t.Run("adopted is skipped", func(t *testing.T) {
		e := newReloc(t)
		e.s.Entries["b"].Files[0].Adopted = true
		e.plan(t, FilesMove, nil)
		if got := strings.Join(actions(e.s.Relocation), " "); got != "a:rename a:rename b:skip" {
			t.Fatal(got)
		}
	})
	t.Run("dir to pve is flat", func(t *testing.T) {
		e := newReloc(t)
		e.to = Layout{Mode: ModePVE, Root: e.to.Root}
		e.plan(t, FilesMove, nil)
		for _, it := range e.s.Relocation.Items {
			if it.ToRel != filepath.Base(it.FromRel) {
				t.Fatalf("%+v", it)
			}
		}
	})
}

func TestPlanRefusals(t *testing.T) {
	t.Run("same location", func(t *testing.T) {
		e := newReloc(t)
		e.to = Layout{Mode: ModeDir, Root: e.from.Root + "/"}
		if _, err := PlanRelocation(e.s, e.from, e.to, FilesMove, nil); err == nil {
			t.Fatal("want a refusal")
		}
	})
	t.Run("same root, other mode is allowed", func(t *testing.T) {
		e := newReloc(t)
		e.to = Layout{Mode: ModePVE, Root: e.from.Root}
		if _, err := PlanRelocation(e.s, e.from, e.to, FilesMove, nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("destination holds a different file", func(t *testing.T) {
		e := newReloc(t)
		write(t, e.to.Abs("a/a-2.iso"), "someone else's")
		_, err := PlanRelocation(e.s, e.from, e.to, FilesMove, nil)
		if !errors.Is(err, ErrExists) {
			t.Fatalf("err=%v", err)
		}
		if read(t, e.to.Abs("a/a-2.iso")) != "someone else's" {
			t.Fatal("touched the destination")
		}
	})
	t.Run("destination holds the same file", func(t *testing.T) {
		e := newReloc(t)
		write(t, e.to.Abs("a/a-2.iso"), "content of a-2.iso")
		if _, err := PlanRelocation(e.s, e.from, e.to, FilesMove, nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("leave mode ignores the destination", func(t *testing.T) {
		e := newReloc(t)
		write(t, e.to.Abs("a/a-2.iso"), "someone else's")
		if _, err := PlanRelocation(e.s, e.from, e.to, FilesLeave, nil); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("two files for one flat name", func(t *testing.T) {
		e := newReloc(t)
		e.s.Entry("c").Files = []FileRecord{recOf("c/b-1.iso", "x", 0)}
		e.to = Layout{Mode: ModePVE, Root: e.to.Root}
		if _, err := PlanRelocation(e.s, e.from, e.to, FilesMove, nil); err == nil {
			t.Fatal("want a refusal")
		}
	})
	t.Run("bad file mode", func(t *testing.T) {
		e := newReloc(t)
		if _, err := PlanRelocation(e.s, e.from, e.to, "sideways", nil); err == nil {
			t.Fatal("want a refusal")
		}
	})
}

func TestRunRelocation(t *testing.T) {
	for _, copyPath := range []bool{false, true} {
		name := "rename"
		if copyPath {
			name = "copy"
		}
		t.Run(name, func(t *testing.T) {
			if copyPath {
				forceCopy(t)
			}
			e := newReloc(t)
			e.plan(t, FilesMove, nil)
			saves, progressed := 0, 0
			var lastDone int
			err := RunRelocation(e.s, func() error { saves++; return e.save() }, func(it RelocItem, done, total int) {
				progressed++
				lastDone = done
				if total != 3 || !it.Done {
					t.Errorf("progress %+v %d/%d", it, done, total)
				}
			})
			if err != nil {
				t.Fatal(err)
			}
			if saves != 4 || progressed != 3 || lastDone != 3 {
				t.Fatalf("saves=%d progressed=%d done=%d", saves, progressed, lastDone)
			}
			if e.s.Relocation != nil || e.s.Root != e.to.Root || e.s.Mode != ModeDir {
				t.Fatalf("state not switched: %+v", e.s)
			}
			for _, rel := range []string{"a/a-2.iso", "a/a-1.iso", "b/b-1.iso"} {
				if !exists(e.to.Abs(rel)) || exists(e.from.Abs(rel)) {
					t.Fatalf("%s not moved", rel)
				}
				if exists(e.to.Abs(rel) + ".part") {
					t.Fatalf("%s.part left behind", rel)
				}
			}
			loaded, err := LoadState(e.statePath)
			if err != nil || loaded.Relocation != nil || len(loaded.Entries["a"].Files) != 2 {
				t.Fatalf("saved state: %+v err=%v", loaded, err)
			}
			for _, f := range e.s.Entries["a"].Files {
				if f.Adopted || !exists(e.to.Abs(f.Rel)) {
					t.Fatalf("record %+v", f)
				}
			}
		})
	}
}

func TestRunRelocationToPVEUpdatesRels(t *testing.T) {
	e := newReloc(t)
	e.to = Layout{Mode: ModePVE, Root: e.to.Root}
	e.s.Entries["a"].Kept = []KeptNote{{Rel: "a/a-1.iso", Reason: "in use by VM 1"}}
	e.plan(t, FilesMove, nil)
	if err := RunRelocation(e.s, e.save, nil); err != nil {
		t.Fatal(err)
	}
	if e.s.Mode != ModePVE || e.s.Entries["a"].Files[1].Rel != "a-1.iso" || e.s.Entries["a"].Kept[0].Rel != "a-1.iso" {
		t.Fatalf("%+v", e.s.Entries["a"])
	}
	if !exists(e.to.Abs("a-1.iso")) {
		t.Fatal("not flat")
	}
}

func TestRunRelocationInterruptedThenResumed(t *testing.T) {
	forceCopy(t)
	e := newReloc(t)
	e.plan(t, FilesMove, nil)
	if err := e.save(); err != nil {
		t.Fatal(err)
	}
	calls := 0
	crash := func() error {
		calls++
		if calls == 2 { // item 2 is on disk, but its Done flag never reaches state
			return errors.New("power cut")
		}
		return e.save()
	}
	if err := RunRelocation(e.s, crash, nil); err == nil {
		t.Fatal("want the interruption")
	}
	// Fresh process: reload what reached the disk.
	s, err := LoadState(e.statePath)
	if err != nil {
		t.Fatal(err)
	}
	if s.Relocation == nil || !s.Relocation.Items[0].Done || s.Relocation.Items[1].Done {
		t.Fatalf("journal: %+v", s.Relocation)
	}
	if !exists(e.to.Abs("a/a-2.iso")) || exists(e.from.Abs("a/a-2.iso")) {
		t.Fatal("first item should be moved")
	}
	var seen []string
	if err := RunRelocation(s, func() error { return s.Save(e.statePath) }, func(it RelocItem, _, _ int) {
		seen = append(seen, it.FromRel)
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(seen, " ") != "a/a-1.iso b/b-1.iso" {
		t.Fatalf("done items must be skipped, ran %v", seen)
	}
	for _, rel := range []string{"a/a-2.iso", "a/a-1.iso", "b/b-1.iso"} {
		if !exists(e.to.Abs(rel)) || exists(e.from.Abs(rel)) {
			t.Fatalf("%s not moved", rel)
		}
	}
	for _, f := range s.Entries["a"].Files {
		if f.Adopted {
			t.Fatal("our own copy must not be marked adopted")
		}
	}
}

func TestRunRelocationCopyKeep(t *testing.T) {
	e := newReloc(t)
	protect := func(rel string) string {
		if rel == "a/a-1.iso" {
			return "in use by VM 105"
		}
		return ""
	}
	e.plan(t, FilesMove, protect)
	if err := RunRelocation(e.s, e.save, nil); err != nil {
		t.Fatal(err)
	}
	if !exists(e.from.Abs("a/a-1.iso")) || !exists(e.to.Abs("a/a-1.iso")) {
		t.Fatal("protected file must be copied, source kept")
	}
	if exists(e.from.Abs("a/a-2.iso")) || !exists(e.to.Abs("a/a-2.iso")) {
		t.Fatal("unprotected file must be moved")
	}
}

func TestRunRelocationCopyMode(t *testing.T) {
	e := newReloc(t)
	e.plan(t, FilesCopy, nil)
	if err := RunRelocation(e.s, e.save, nil); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{"a/a-2.iso", "a/a-1.iso", "b/b-1.iso"} {
		if !exists(e.from.Abs(rel)) || !exists(e.to.Abs(rel)) {
			t.Fatalf("%s: both copies must exist", rel)
		}
	}
	if e.s.Root != e.to.Root || len(e.s.Entries["a"].Files) != 2 {
		t.Fatalf("%+v", e.s)
	}
}

func TestRunRelocationLeaveMode(t *testing.T) {
	e := newReloc(t)
	e.plan(t, FilesLeave, nil)
	if err := RunRelocation(e.s, e.save, nil); err != nil {
		t.Fatal(err)
	}
	if len(e.s.Entries["a"].Files) != 0 || len(e.s.Entries["b"].Files) != 0 {
		t.Fatal("records should be dropped")
	}
	if e.s.Root != e.to.Root || e.s.Relocation != nil {
		t.Fatalf("%+v", e.s)
	}
	for _, rel := range []string{"a/a-2.iso", "a/a-1.iso", "b/b-1.iso"} {
		if !exists(e.from.Abs(rel)) {
			t.Fatalf("%s was touched", rel)
		}
	}
	if exists(e.to.Root) {
		t.Fatal("leave mode must not create the destination")
	}
}

func TestRunRelocationAdoptedStays(t *testing.T) {
	e := newReloc(t)
	e.s.Entries["b"].Files[0].Adopted = true
	e.plan(t, FilesMove, nil)
	if err := RunRelocation(e.s, e.save, nil); err != nil {
		t.Fatal(err)
	}
	if len(e.s.Entries["b"].Files) != 0 || !exists(e.from.Abs("b/b-1.iso")) || exists(e.to.Abs("b/b-1.iso")) {
		t.Fatal("adopted file must stay put with its record dropped")
	}
}

func TestRunRelocationDestinationAppearsLater(t *testing.T) {
	forceCopy(t)
	e := newReloc(t)
	e.plan(t, FilesMove, nil)
	write(t, e.to.Abs("b/b-1.iso"), "someone else's")
	err := RunRelocation(e.s, e.save, nil)
	if !errors.Is(err, ErrExists) {
		t.Fatalf("err=%v", err)
	}
	if read(t, e.to.Abs("b/b-1.iso")) != "someone else's" || !exists(e.from.Abs("b/b-1.iso")) {
		t.Fatal("both files must stay")
	}
	if e.s.Relocation == nil {
		t.Fatal("journal must stay for a resume")
	}
}

func TestRunRelocationIdenticalDestinationCountsAsDone(t *testing.T) {
	forceCopy(t)
	e := newReloc(t)
	write(t, e.to.Abs("b/b-1.iso"), "content of b-1.iso")
	e.plan(t, FilesMove, nil)
	if err := RunRelocation(e.s, e.save, nil); err != nil {
		t.Fatal(err)
	}
	f := e.s.Entries["b"].Files[0]
	if !f.Adopted || exists(e.from.Abs("b/b-1.iso")) || read(t, e.to.Abs("b/b-1.iso")) != "content of b-1.iso" {
		t.Fatalf("%+v", f)
	}
}

func TestRunRelocationBadCopyIsRejected(t *testing.T) {
	forceCopy(t)
	e := newReloc(t)
	e.s.Entries["b"].Files[0].Hash = strings.Repeat("0", 64)
	e.plan(t, FilesMove, nil)
	err := RunRelocation(e.s, e.save, nil)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("err=%v", err)
	}
	if exists(e.to.Abs("b/b-1.iso")) || exists(e.to.Abs("b/b-1.iso.part")) || !exists(e.from.Abs("b/b-1.iso")) {
		t.Fatal("a bad copy must leave nothing behind, and the source stays")
	}
}

func TestRunRelocationNothingToDo(t *testing.T) {
	if err := RunRelocation(&State{}, func() error { return nil }, nil); err == nil {
		t.Fatal("want an error")
	}
}

func TestSameFilesystem(t *testing.T) {
	dir := t.TempDir()
	same, err := SameFilesystem(dir, filepath.Join(dir, "does", "not", "exist"))
	if err != nil || !same {
		t.Fatalf("same=%v err=%v", same, err)
	}
	if same, err := SameFilesystem("/proc", dir); err != nil || same {
		t.Fatalf("/proc vs temp: same=%v err=%v", same, err)
	}
}
