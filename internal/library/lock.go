package library

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrLocked means another cerberus run holds the lock.
var ErrLocked = errors.New("another cerberus run is in progress")

// Lock is an exclusive run lock (flock).
type Lock struct{ f *os.File }

// AcquireLock takes the lock at path without waiting, creating the file and
// its folder if needed. It returns ErrLocked when another process holds it.
func AcquireLock(path string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return &Lock{f: f}, nil
}

// Release drops the lock.
func (l *Lock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	f := l.f
	l.f = nil
	uerr := unix.Flock(int(f.Fd()), unix.LOCK_UN)
	if err := f.Close(); err != nil && uerr == nil {
		return err
	}
	return uerr
}

// OwnerFile is the marker cerberus writes in the library root. It is a
// dotfile, so PVE doesn't list it.
const OwnerFile = ".cerberus-owner"

// ErrOtherOwner means another host manages the library.
var ErrOtherOwner = errors.New("this library is managed by another host")

// ClaimOwner writes machineID to <root>/.cerberus-owner when the marker is
// missing, or when takeOver is set. It returns an error wrapping
// ErrOtherOwner, naming the other ID, when the marker holds a different
// ID.
func ClaimOwner(root, machineID string, takeOver bool) error {
	path := filepath.Join(root, OwnerFile)
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	other := strings.TrimSpace(string(data))
	if other == machineID {
		return nil
	}
	if other != "" && !takeOver {
		return fmt.Errorf("%w: %s", ErrOtherOwner, other)
	}
	return atomicWrite(path, []byte(machineID+"\n"))
}
