package library

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestPlace(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		name := "renameat2"
		if fallback {
			name = "fallback"
		}
		t.Run(name, func(t *testing.T) {
			if fallback {
				old := renameNoReplace
				renameNoReplace = func(a, b string) error { return unix.EINVAL }
				t.Cleanup(func() { renameNoReplace = old })
			}
			dir := t.TempDir()
			sum := sumOf("iso bytes")

			t.Run("plain success", func(t *testing.T) {
				part, dst := filepath.Join(dir, "p1.part"), filepath.Join(dir, "new", "sub", "a.iso")
				write(t, part, "iso bytes")
				adopted, err := Place(part, dst, sum)
				if err != nil || adopted {
					t.Fatalf("adopted=%v err=%v", adopted, err)
				}
				if read(t, dst) != "iso bytes" || exists(part) {
					t.Fatal("file not moved")
				}
			})
			t.Run("adopts identical", func(t *testing.T) {
				part, dst := filepath.Join(dir, "p2.part"), filepath.Join(dir, "b.iso")
				write(t, part, "iso bytes")
				write(t, dst, "iso bytes")
				adopted, err := Place(part, dst, sum)
				if err != nil || !adopted {
					t.Fatalf("adopted=%v err=%v", adopted, err)
				}
				if !exists(part) || read(t, dst) != "iso bytes" {
					t.Fatal("both files must stay: the caller removes the part file after saving the adoption")
				}
			})
			t.Run("refuses a different file", func(t *testing.T) {
				part, dst := filepath.Join(dir, "p3.part"), filepath.Join(dir, "c.iso")
				write(t, part, "iso bytes")
				write(t, dst, "someone else's")
				adopted, err := Place(part, dst, sum)
				if !errors.Is(err, ErrExists) || adopted {
					t.Fatalf("adopted=%v err=%v", adopted, err)
				}
				if read(t, part) != "iso bytes" || read(t, dst) != "someone else's" {
					t.Fatal("both files must stay")
				}
			})
			t.Run("refuses a symlink at dst", func(t *testing.T) {
				part, dst := filepath.Join(dir, "p4.part"), filepath.Join(dir, "d.iso")
				write(t, part, "iso bytes")
				write(t, filepath.Join(dir, "target"), "iso bytes")
				if err := os.Symlink("target", dst); err != nil {
					t.Fatal(err)
				}
				if _, err := Place(part, dst, sum); !errors.Is(err, ErrExists) {
					t.Fatalf("err=%v", err)
				}
				if !exists(part) {
					t.Fatal("part must stay")
				}
			})
		})
	}
}

func TestPlaceFallbackUsedOnENOSYS(t *testing.T) {
	old := renameNoReplace
	calls := 0
	renameNoReplace = func(a, b string) error { calls++; return unix.EOPNOTSUPP }
	t.Cleanup(func() { renameNoReplace = old })
	dir := t.TempDir()
	write(t, filepath.Join(dir, "x.part"), "z")
	if _, err := Place(filepath.Join(dir, "x.part"), filepath.Join(dir, "x.iso"), sumOf("z")); err != nil || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
	if read(t, filepath.Join(dir, "x.iso")) != "z" {
		t.Fatal("not placed")
	}
}

func TestAliases(t *testing.T) {
	root := t.TempDir()
	l := Layout{Mode: ModeDir, Root: root, Aliases: true}
	write(t, l.Abs("alpine/a-1.iso"), "one")
	write(t, l.Abs("alpine/a-2.iso"), "two")
	alias := l.AliasPath("alpine")

	if err := SetAlias(l, "alpine", "alpine/a-1.iso"); err != nil {
		t.Fatal(err)
	}
	target, err := os.Readlink(alias)
	if err != nil || target != filepath.Join("..", "alpine", "a-1.iso") {
		t.Fatalf("target=%q err=%v", target, err)
	}
	if read(t, alias) != "one" {
		t.Fatal("link does not resolve")
	}
	if err := SetAlias(l, "alpine", "alpine/a-2.iso"); err != nil {
		t.Fatal(err)
	}
	if read(t, alias) != "two" {
		t.Fatal("link not replaced")
	}
	ents, _ := os.ReadDir(filepath.Dir(alias))
	if len(ents) != 1 {
		t.Fatalf("temp links left behind: %v", ents)
	}

	if err := RemoveAlias(l, "alpine"); err != nil || exists(alias) {
		t.Fatalf("remove: %v", err)
	}
	if !exists(l.Abs("alpine/a-2.iso")) {
		t.Fatal("remove touched the target")
	}
	if err := RemoveAlias(l, "alpine"); err != nil {
		t.Fatalf("missing alias should be fine: %v", err)
	}

	write(t, alias, "a real file")
	if err := SetAlias(l, "alpine", "alpine/a-1.iso"); err == nil {
		t.Fatal("want a refusal")
	}
	if err := RemoveAlias(l, "alpine"); err != nil {
		t.Fatal(err)
	}
	if read(t, alias) != "a real file" {
		t.Fatal("non-symlink was touched")
	}
}

func TestAliasesDisabled(t *testing.T) {
	root := t.TempDir()
	for _, l := range []Layout{
		{Mode: ModeDir, Root: root},
		{Mode: ModePVE, Root: root, Aliases: true},
	} {
		if err := SetAlias(l, "x", "x.iso"); err != nil {
			t.Fatal(err)
		}
		if err := RemoveAlias(l, "x"); err != nil {
			t.Fatal(err)
		}
	}
	if exists(filepath.Join(root, "latest")) {
		t.Fatal("latest/ created without aliases")
	}
}
