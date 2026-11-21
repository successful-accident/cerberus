package library

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// ProtectFunc returns a non-empty reason when the file at rel must stay on
// disk, for example "in use by VM 105".
type ProtectFunc func(rel string) (reason string)

// Prune keeps the first keep records of es.Files (newest Added first) and
// deals with the rest:
//   - a protected file stays, both on disk and in state, with a KeptNote;
//   - an adopted file's record is dropped and the file stays on disk;
//   - any other file is deleted, then its record is dropped.
//
// It resets es.Kept and returns the deleted records. A keep below 1 is
// treated as 1. A file that's already gone counts as deleted.
func Prune(l Layout, es *EntryState, keep int, protect ProtectFunc) (removed []FileRecord, err error) {
	if keep < 1 {
		keep = 1
	}
	es.Kept = nil
	if len(es.Files) <= keep {
		return nil, nil
	}
	files := append([]FileRecord(nil), es.Files[:keep]...)
	for i := keep; i < len(es.Files); i++ {
		rec := es.Files[i]
		if protect != nil {
			if reason := protect(rec.Rel); reason != "" {
				files = append(files, rec)
				es.Kept = append(es.Kept, KeptNote{Rel: rec.Rel, Reason: reason})
				continue
			}
		}
		if rec.Adopted {
			continue
		}
		if !filepath.IsLocal(rec.Rel) {
			err = fmt.Errorf("refusing to delete %q: not a path inside the library", rec.Rel)
		} else if rerr := os.Remove(l.Abs(rec.Rel)); rerr != nil && !errors.Is(rerr, fs.ErrNotExist) {
			err = fmt.Errorf("delete %s: %w", l.Abs(rec.Rel), rerr)
		}
		if err != nil {
			// Keep this record and the rest, so state matches the disk.
			es.Files = append(files, es.Files[i:]...)
			return removed, err
		}
		removed = append(removed, rec)
	}
	es.Files = files
	return removed, nil
}

// Reconcile repairs state after a crash and returns notes for the user.
//
// If s.Pending is set, the placement is finished when its destination
// exists with the recorded size and checksum: the record is added to the
// entry if missing. If the part file is still there too, the rename never
// happened, since Place leaves the part file when it adopts, so the record
// is marked Adopted and the part file is removed. Otherwise
// the pending record is dropped, and the part file is kept as a resumable
// Partial if it still exists. Partials for entries that are no longer
// selected, as reported by selected(id), are deleted with their .meta
// files. Reconcile never touches a file that state doesn't name. It doesn't
// save; the caller does.
func Reconcile(l Layout, s *State, selected func(id string) bool) (notes []string, err error) {
	if p := s.Pending; p != nil {
		note, err := reconcilePending(l, s, p)
		if err != nil {
			return nil, err
		}
		notes = append(notes, note)
		s.Pending = nil
	}
	keys := make([]string, 0, len(s.Partials))
	for k := range s.Partials {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		pt := s.Partials[k]
		if selected(pt.Entry) {
			continue
		}
		if !filepath.IsLocal(k) {
			return notes, fmt.Errorf("refusing to delete partial %q: not a path inside the library", k)
		}
		part := l.Abs(k)
		for _, p := range []string{part, part + ".meta"} {
			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return notes, fmt.Errorf("delete partial %s: %w", p, err)
			}
		}
		delete(s.Partials, k)
		notes = append(notes, fmt.Sprintf("Deleted the unfinished download %s, because %s is no longer selected.", k, pt.Entry))
	}
	return notes, nil
}

func reconcilePending(l Layout, s *State, p *Pending) (string, error) {
	dst, part := l.Abs(p.File.Rel), l.Abs(p.Part)
	partLeft := false
	if _, err := os.Lstat(part); err == nil {
		partLeft = true
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}

	finished := false
	if fi, err := os.Lstat(dst); err == nil {
		if fi.Mode().IsRegular() && fi.Size() == p.File.Size {
			if finished, err = p.File.Checksum().MatchFile(dst); err != nil {
				return "", fmt.Errorf("check %s: %w", dst, err)
			}
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}

	if finished {
		rec := p.File
		if partLeft {
			// The rename never happened, so the file was already there.
			rec.Adopted = true
			if err := os.Remove(part); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return "", err
			}
		}
		es := s.Entry(p.Entry)
		have := false
		for _, f := range es.Files {
			have = have || f.Rel == rec.Rel
		}
		if !have {
			es.Files = append(es.Files, rec)
			sort.SliceStable(es.Files, func(i, j int) bool { return es.Files[i].Added.After(es.Files[j].Added) })
		}
		return fmt.Sprintf("Finished placing %s for %s after an interrupted run.", p.File.Rel, p.Entry), nil
	}

	note := fmt.Sprintf("Rolled back the interrupted placement of %s for %s.", p.File.Rel, p.Entry)
	if partLeft {
		if s.Partials == nil {
			s.Partials = map[string]Partial{}
		}
		if _, ok := s.Partials[p.Part]; !ok {
			s.Partials[p.Part] = Partial{Entry: p.Entry, Version: p.File.Version}
		}
		note += " Kept the downloaded file to resume from."
	}
	return note, nil
}
