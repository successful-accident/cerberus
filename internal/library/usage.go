package library

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Usage summarizes disk use for the status screen.
type Usage struct {
	Managed int64  // bytes in files state records
	Other   int64  // bytes in other regular files in the library folders
	Avail   uint64 // available on the library's filesystem
	Total   uint64 // filesystem size
}

// DiskUsage measures the library. In dir mode it walks the whole root; in
// PVE mode it reads only the ISO folder, without recursing. It skips the
// owner marker, aliases, and part files that state knows about.
func DiskUsage(l Layout, s *State) (Usage, error) {
	var u Usage
	skip := map[string]bool{filepath.Join(l.Root, OwnerFile): true}
	for _, es := range s.Entries {
		for _, rec := range es.Files {
			p := l.Abs(rec.Rel)
			skip[p] = true
			if fi, err := os.Stat(p); err == nil {
				u.Managed += fi.Size()
			} else if !errors.Is(err, fs.ErrNotExist) {
				return u, err
			}
		}
	}
	for part := range s.Partials {
		skip[l.Abs(part)], skip[l.Abs(part)+".meta"] = true, true
	}
	if s.Pending != nil {
		skip[l.Abs(s.Pending.Part)], skip[l.Abs(s.Pending.Part)+".meta"] = true, true
	}

	add := func(p string, d fs.DirEntry) error {
		if !d.Type().IsRegular() || skip[p] {
			return nil
		}
		fi, err := d.Info()
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		u.Other += fi.Size()
		return nil
	}
	if l.Mode == ModePVE {
		ents, err := os.ReadDir(l.Root)
		if err != nil {
			return u, err
		}
		for _, d := range ents {
			if err := add(filepath.Join(l.Root, d.Name()), d); err != nil {
				return u, err
			}
		}
	} else {
		latest := filepath.Join(l.Root, "latest")
		err := filepath.WalkDir(l.Root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if p == l.Root {
					return err
				}
				if d != nil && d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if d.IsDir() && p == latest {
				return fs.SkipDir
			}
			return add(p, d)
		})
		if err != nil {
			return u, err
		}
	}

	var st unix.Statfs_t
	if err := unix.Statfs(l.Root, &st); err != nil {
		return u, err
	}
	u.Avail = uint64(st.Bavail) * uint64(st.Bsize)
	u.Total = uint64(st.Blocks) * uint64(st.Bsize)
	return u, nil
}
