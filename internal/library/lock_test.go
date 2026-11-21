package library

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "var", "lib", "cerberus.lock")
	a, err := AcquireLock(path)
	if err != nil {
		t.Fatal(err)
	}
	if b, err := AcquireLock(path); !errors.Is(err, ErrLocked) || b != nil {
		t.Fatalf("second lock: %v %v", b, err)
	}
	if err := a.Release(); err != nil {
		t.Fatal(err)
	}
	c, err := AcquireLock(path)
	if err != nil {
		t.Fatalf("after release: %v", err)
	}
	if err := c.Release(); err != nil {
		t.Fatal(err)
	}
	if err := c.Release(); err != nil {
		t.Fatalf("double release: %v", err)
	}
}

func TestClaimOwner(t *testing.T) {
	root := t.TempDir()
	marker := filepath.Join(root, OwnerFile)

	if err := ClaimOwner(root, "host-a", false); err != nil {
		t.Fatal(err)
	}
	if read(t, marker) != "host-a\n" {
		t.Fatalf("marker=%q", read(t, marker))
	}
	if err := ClaimOwner(root, "host-a", false); err != nil {
		t.Fatalf("same ID: %v", err)
	}
	err := ClaimOwner(root, "host-b", false)
	if !errors.Is(err, ErrOtherOwner) || !strings.Contains(err.Error(), "host-a") {
		t.Fatalf("other ID: %v", err)
	}
	if read(t, marker) != "host-a\n" {
		t.Fatal("marker changed without takeOver")
	}
	if err := ClaimOwner(root, "host-b", true); err != nil {
		t.Fatal(err)
	}
	if read(t, marker) != "host-b\n" {
		t.Fatalf("marker=%q", read(t, marker))
	}
	if ents, _ := os.ReadDir(root); len(ents) != 1 {
		t.Fatalf("temp files left behind: %v", ents)
	}
}

func TestClaimOwnerTrimsMarker(t *testing.T) {
	root := t.TempDir()
	write(t, filepath.Join(root, OwnerFile), "  host-a \r\n\n")
	if err := ClaimOwner(root, "host-a", false); err != nil {
		t.Fatal(err)
	}
}
