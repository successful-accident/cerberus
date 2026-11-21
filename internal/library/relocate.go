package library

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"golang.org/x/sys/unix"
)

// sameFS is SameFilesystem; tests swap it to force the copy path.
var sameFS = SameFilesystem

// PlanRelocation builds the journal for moving every file in s from one
// layout to another, recomputing each file's relative path for the new
// mode. Per file:
//   - FilesLeave, or an adopted file: ActSkip.
//   - FilesCopy: ActCopyKeep.
//   - FilesMove, protected: ActCopyKeep, with the protect reason.
//   - FilesMove, same filesystem: ActRename.
//   - FilesMove otherwise: ActCopy.
//
// It refuses when the destination already holds a different file at any
// target path, and when from and to are the same location.
func PlanRelocation(s *State, from, to Layout, files FileMode, protect ProtectFunc) (*Relocation, error) {
	if from.Mode == to.Mode && filepath.Clean(from.Root) == filepath.Clean(to.Root) {
		return nil, fmt.Errorf("the library is already at %s (%s mode)", from.Root, from.Mode)
	}
	switch files {
	case FilesMove, FilesCopy, FilesLeave:
	default:
		return nil, fmt.Errorf("unknown file mode %q", files)
	}
	r := &Relocation{
		FromMode: from.Mode, FromRoot: from.Root,
		ToMode: to.Mode, ToRoot: to.Root,
		Files: files,
	}
	ids := make([]string, 0, len(s.Entries))
	for id := range s.Entries {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	targets := map[string]string{}
	for _, id := range ids {
		for _, rec := range s.Entries[id].Files {
			it := RelocItem{Entry: id, FromRel: rec.Rel, ToRel: to.Rel(id, filepath.Base(rec.Rel))}
			switch {
			case files == FilesLeave:
				it.Action, it.Reason = ActSkip, "files are left where they are"
			case rec.Adopted:
				it.Action, it.Reason = ActSkip, "adopted file, not ours to move"
			case files == FilesCopy:
				it.Action = ActCopyKeep
			default:
				if reason := protectReason(protect, rec.Rel); reason != "" {
					it.Action, it.Reason = ActCopyKeep, reason
				} else if same, err := sameFS(from.Abs(rec.Rel), to.Abs(it.ToRel)); err != nil {
					return nil, fmt.Errorf("compare filesystems for %s: %w", rec.Rel, err)
				} else if same {
					it.Action = ActRename
				} else {
					it.Action = ActCopy
				}
			}
			if it.Action != ActSkip {
				if other, dup := targets[it.ToRel]; dup {
					return nil, fmt.Errorf("%s and %s would both go to %s", other, rec.Rel, to.Abs(it.ToRel))
				}
				targets[it.ToRel] = rec.Rel
				exists, same, err := existing(to.Abs(it.ToRel), rec.Checksum())
				if err != nil {
					return nil, fmt.Errorf("check %s: %w", to.Abs(it.ToRel), err)
				}
				if exists && !same {
					return nil, fmt.Errorf("%w: %s", ErrExists, to.Abs(it.ToRel))
				}
			}
			r.Items = append(r.Items, it)
		}
	}
	return r, nil
}

func protectReason(protect ProtectFunc, rel string) string {
	if protect == nil {
		return ""
	}
	return protect(rel)
}

// RunRelocation executes s.Relocation, or resumes it, one item at a time,
// marking each Done and calling save after each item. Before each item that
// isn't ActSkip, it calls before, when not nil, and stops on its error with
// the journal intact, so a later run resumes; the engine uses it to recheck
// the target. A copy goes to <dst>.part, journaled as Copying before the
// first byte, is verified against the record's checksum, and is renamed
// with Place. A source that's no longer needed (ActCopy and ActRename), and
// a part file an adoption left, are removed only after the save that
// records the item, so a crash never leaves an adopted file looking like
// cerberus's own. A file gone from both places becomes ActSkip, and its
// record is dropped. When every item is done, it deletes the partial
// downloads in s.Partials under the old root, with their .meta files, and
// clears s.Partials; rewrites each FileRecord.Rel; drops skipped records;
// sets s.Mode and s.Root; clears s.Relocation; and calls save one last
// time. progress may be nil.
func RunRelocation(s *State, save func() error, before func(item RelocItem, rec FileRecord) error,
	progress func(item RelocItem, done, total int)) error {
	r := s.Relocation
	if r == nil {
		return errors.New("no relocation in progress")
	}
	from := Layout{Mode: r.FromMode, Root: r.FromRoot}
	to := Layout{Mode: r.ToMode, Root: r.ToRoot}
	total, done := len(r.Items), 0
	for _, it := range r.Items {
		if it.Done {
			done++
		}
	}
	for i := range r.Items {
		it := &r.Items[i]
		if it.Done {
			continue
		}
		rec := findRecord(s, it.Entry, it.FromRel)
		if rec == nil {
			return fmt.Errorf("relocate %s: no record for %s", it.Entry, it.FromRel)
		}
		if before != nil && it.Action != ActSkip {
			if err := before(*it, *rec); err != nil {
				return fmt.Errorf("relocate %s: %w", it.Entry, err)
			}
		}
		leftovers, err := relocateOne(from, to, it, rec, save)
		if err != nil {
			return fmt.Errorf("relocate %s: %w", it.Entry, err)
		}
		it.Done = true
		done++
		if err := save(); err != nil {
			return err
		}
		for _, p := range leftovers {
			if err := removeFile(p); err != nil {
				return fmt.Errorf("relocate %s: %w", it.Entry, err)
			}
		}
		if progress != nil {
			progress(*it, done, total)
		}
	}

	// The old root's partial downloads are cerberus's own, and a key would
	// name a path under the new root once Root changes.
	for k := range s.Partials {
		if !filepath.IsLocal(k) {
			return fmt.Errorf("refusing to delete partial %q: not a path inside the library", k)
		}
		for _, p := range []string{from.Abs(k), from.Abs(k) + ".meta"} {
			if err := removeFile(p); err != nil {
				return fmt.Errorf("delete partial %s: %w", p, err)
			}
		}
	}
	s.Partials = nil

	moved := map[string]string{} // entry + "\x00" + old rel -> new rel
	dropped := map[string]bool{}
	for _, it := range r.Items {
		key := it.Entry + "\x00" + it.FromRel
		if it.Action == ActSkip {
			dropped[key] = true
		} else {
			moved[key] = it.ToRel
		}
	}
	for id, es := range s.Entries {
		files := es.Files[:0]
		for _, rec := range es.Files {
			key := id + "\x00" + rec.Rel
			if dropped[key] {
				continue
			}
			if rel, ok := moved[key]; ok {
				rec.Rel = rel
			}
			files = append(files, rec)
		}
		es.Files = files
		kept := es.Kept[:0]
		for _, k := range es.Kept {
			key := id + "\x00" + k.Rel
			if dropped[key] {
				continue
			}
			if rel, ok := moved[key]; ok {
				k.Rel = rel
			}
			kept = append(kept, k)
		}
		es.Kept = kept
	}
	s.Mode, s.Root = r.ToMode, r.ToRoot
	s.Relocation = nil
	return save()
}

func findRecord(s *State, entry, rel string) *FileRecord {
	es := s.Entries[entry]
	if es == nil {
		return nil
	}
	for i := range es.Files {
		if es.Files[i].Rel == rel {
			return &es.Files[i]
		}
	}
	return nil
}

// relocateOne moves, or copies, one file, and returns the files to remove
// once the item is saved as done. A destination that already holds the file
// counts as done. It is cerberus's own when a rename consumed the source or
// a journaled copy's part file was renamed; otherwise the file was already
// in the destination, so its record is marked adopted and cerberus never
// deletes it.
func relocateOne(from, to Layout, it *RelocItem, rec *FileRecord, save func() error) (leftovers []string, err error) {
	if it.Action == ActSkip {
		return nil, nil
	}
	if !filepath.IsLocal(it.FromRel) || !filepath.IsLocal(it.ToRel) {
		return nil, fmt.Errorf("refusing paths outside the library: %q, %q", it.FromRel, it.ToRel)
	}
	src, dst := from.Abs(it.FromRel), to.Abs(it.ToRel)
	part := dst + ".part"
	sum := rec.Checksum()
	moves := it.Action == ActCopy || it.Action == ActRename

	srcGone, err := missing(src)
	if err != nil {
		return nil, err
	}
	partLeft := false
	if it.Copying {
		gone, err := missing(part)
		if err != nil {
			return nil, err
		}
		if partLeft = !gone; partLeft {
			leftovers = append(leftovers, part)
		}
	}
	exists, same, err := existing(dst, sum)
	if err != nil {
		return nil, fmt.Errorf("check %s: %w", dst, err)
	}
	if exists && !same {
		return nil, fmt.Errorf("%w: %s", ErrExists, dst)
	}
	if exists {
		ours := it.Action == ActRename && srcGone || it.Copying && !partLeft
		rec.Adopted = rec.Adopted || !ours
		if moves && !srcGone {
			leftovers = append(leftovers, src)
		}
		return leftovers, nil
	}
	if srcGone {
		it.Action, it.Reason = ActSkip, "the file was already gone"
		return leftovers, nil
	}

	if it.Action == ActRename {
		adopted, err := Place(src, dst, sum)
		if err != nil {
			return nil, err
		}
		if adopted {
			rec.Adopted = true
			leftovers = append(leftovers, src)
		}
		return leftovers, nil
	}
	if !it.Copying {
		if gone, err := missing(part); err != nil {
			return nil, err
		} else if !gone {
			return nil, fmt.Errorf("%s is in the way, and cerberus didn't write it", part)
		}
		it.Copying = true
		if err := save(); err != nil {
			return nil, err
		}
	}
	if err := copyFile(src, part); err != nil {
		return nil, err
	}
	if ok, err := sum.MatchFile(part); err != nil || !ok {
		os.Remove(part)
		if err != nil {
			return nil, fmt.Errorf("verify copy of %s: %w", src, err)
		}
		return nil, fmt.Errorf("copy of %s does not match its recorded %s checksum", src, sum.Algo)
	}
	adopted, err := Place(part, dst, sum)
	if err != nil {
		return nil, err
	}
	leftovers = nil
	if adopted {
		rec.Adopted = true
		leftovers = append(leftovers, part)
	}
	if moves {
		leftovers = append(leftovers, src)
	}
	return leftovers, nil
}

// missing reports whether nothing exists at p.
func missing(p string) (bool, error) {
	_, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return true, nil
	}
	return false, err
}

func removeFile(p string) error {
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

func copyFile(src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			out.Close()
			os.Remove(dst)
		}
	}()
	if _, err = io.Copy(out, in); err != nil {
		return fmt.Errorf("copy %s to %s: %w", src, dst, err)
	}
	if err = out.Sync(); err != nil {
		return err
	}
	return out.Close()
}

// SameFilesystem reports whether a and b, or their nearest existing
// ancestors, are on the same device.
func SameFilesystem(a, b string) (bool, error) {
	da, err := deviceOf(a)
	if err != nil {
		return false, err
	}
	db, err := deviceOf(b)
	if err != nil {
		return false, err
	}
	return da == db, nil
}

func deviceOf(p string) (uint64, error) {
	p = filepath.Clean(p)
	for {
		var st unix.Stat_t
		err := unix.Stat(p, &st)
		if err == nil {
			return uint64(st.Dev), nil
		}
		parent := filepath.Dir(p)
		if !errors.Is(err, unix.ENOENT) || parent == p {
			return 0, fmt.Errorf("stat %s: %w", p, err)
		}
		p = parent
	}
}
