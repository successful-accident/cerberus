package library

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/successful-accident/cerberus/internal/verify"
)

// ErrExists means the destination holds a different file that cerberus
// didn't write.
var ErrExists = errors.New("a different file already exists at the destination")

// renameNoReplace is renameat2 with RENAME_NOREPLACE. Tests swap it to
// simulate a filesystem that lacks the flag.
var renameNoReplace = func(oldpath, newpath string) error {
	return unix.Renameat2(unix.AT_FDCWD, oldpath, unix.AT_FDCWD, newpath, unix.RENAME_NOREPLACE)
}

// Place renames the verified part file to dst without ever replacing an
// existing file, using renameat2 RENAME_NOREPLACE where the filesystem
// supports it, and otherwise a no-clobber check under the run lock. If dst
// exists with checksum sum, Place reports adopted and leaves the part file
// where it is: the caller saves state with the record marked Adopted, and
// only then removes the part file, so a crash in between still shows both
// files, which Reconcile and RunRelocation read as an adoption. If dst
// exists and differs, it returns ErrExists and leaves both files. It
// creates dst's folder (0755) if needed.
func Place(part, dst string, sum verify.Checksum) (adopted bool, err error) {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return false, err
	}
	err = renameNoReplace(part, dst)
	switch {
	case err == nil:
		return false, nil
	case errors.Is(err, unix.EEXIST):
		return adoptOrRefuse(dst, sum)
	case errors.Is(err, unix.EINVAL), errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EOPNOTSUPP):
		// No RENAME_NOREPLACE here (NFS, for one). The run lock makes a
		// check-then-rename safe against other cerberus runs.
		if _, serr := os.Lstat(dst); serr == nil {
			return adoptOrRefuse(dst, sum)
		} else if !errors.Is(serr, fs.ErrNotExist) {
			return false, serr
		}
		if err := os.Rename(part, dst); err != nil {
			return false, fmt.Errorf("rename %s to %s: %w", part, dst, err)
		}
		return false, nil
	}
	return false, fmt.Errorf("rename %s to %s: %w", part, dst, err)
}

// adoptOrRefuse handles a dst that already exists: an identical regular
// file is adopted, with the part file left for the caller, and anything
// else is ErrExists.
func adoptOrRefuse(dst string, sum verify.Checksum) (bool, error) {
	_, same, err := existing(dst, sum)
	if err != nil {
		return false, err
	}
	if !same {
		return false, fmt.Errorf("%w: %s", ErrExists, dst)
	}
	return true, nil
}

// existing reports whether path exists, and whether it is a regular file
// with checksum sum.
func existing(path string, sum verify.Checksum) (exists, same bool, err error) {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}
	if !fi.Mode().IsRegular() {
		return true, false, nil
	}
	same, err = sum.MatchFile(path)
	return true, same, err
}

// SetAlias points l.AliasPath(entryID) at rel with a relative symlink,
// replacing any old link atomically. It does nothing when the layout has no
// aliases. It refuses to replace anything at the alias path that isn't a
// symlink.
func SetAlias(l Layout, entryID, rel string) error {
	alias := l.AliasPath(entryID)
	if alias == "" {
		return nil
	}
	dir := filepath.Dir(alias)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if fi, err := os.Lstat(alias); err == nil {
		if fi.Mode()&fs.ModeSymlink == 0 {
			return fmt.Errorf("alias %s exists and is not a symlink", alias)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	target, err := filepath.Rel(dir, l.Abs(rel))
	if err != nil {
		return err
	}
	tmp := fmt.Sprintf("%s.tmp-%d-%d", alias, os.Getpid(), time.Now().UnixNano())
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, alias); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("replace alias %s: %w", alias, err)
	}
	return nil
}

// RemoveAlias deletes an entry's alias if it is a symlink.
func RemoveAlias(l Layout, entryID string) error {
	alias := l.AliasPath(entryID)
	if alias == "" {
		return nil
	}
	fi, err := os.Lstat(alias)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&fs.ModeSymlink == 0 {
		return nil
	}
	if err := os.Remove(alias); err != nil && !errors.Is(err, syscall.ENOENT) {
		return err
	}
	return nil
}
