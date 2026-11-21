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
// marking each Done and calling save after each item. A copy goes to
// <dst>.part, is verified against the record's checksum, is renamed with
// Place, and only then is the source removed (ActCopy). When every item is
// done, it rewrites each FileRecord.Rel, drops skipped records, sets s.Mode
// and s.Root, clears s.Relocation, and calls save one last time. progress
// may be nil.
func RunRelocation(s *State, save func() error, progress func(item RelocItem, done, total int)) error {
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
		if err := relocateOne(from, to, it, rec); err != nil {
			return fmt.Errorf("relocate %s: %w", it.Entry, err)
		}
		it.Done = true
		done++
		if err := save(); err != nil {
			return err
		}
		if progress != nil {
			progress(*it, done, total)
		}
	}

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

// relocateOne moves, or copies, one file. A destination that already holds
// the file counts as done: when the source is still there too, the file was
// already in the destination before we got to it, so its record is marked
// adopted and cerberus never deletes it.
func relocateOne(from, to Layout, it *RelocItem, rec *FileRecord) error {
	if it.Action == ActSkip {
		return nil
	}
	if !filepath.IsLocal(it.FromRel) || !filepath.IsLocal(it.ToRel) {
		return fmt.Errorf("refusing paths outside the library: %q, %q", it.FromRel, it.ToRel)
	}
	src, dst := from.Abs(it.FromRel), to.Abs(it.ToRel)
	sum := rec.Checksum()

	_, serr := os.Lstat(src)
	srcGone := errors.Is(serr, fs.ErrNotExist)
	if serr != nil && !srcGone {
		return serr
	}
	exists, same, err := existing(dst, sum)
	if err != nil {
		return fmt.Errorf("check %s: %w", dst, err)
	}
	if exists && !same {
		return fmt.Errorf("%w: %s", ErrExists, dst)
	}
	if exists {
		if !srcGone {
			rec.Adopted = true
			if it.Action == ActCopy || it.Action == ActRename {
				return removeFile(src)
			}
		}
		return nil
	}
	if srcGone {
		return fmt.Errorf("source %s is missing", src)
	}

	if it.Action == ActRename {
		adopted, err := Place(src, dst, sum)
		rec.Adopted = rec.Adopted || adopted
		return err
	}
	if err := copyFile(src, dst+".part"); err != nil {
		return err
	}
	if ok, err := sum.MatchFile(dst + ".part"); err != nil || !ok {
		os.Remove(dst + ".part")
		if err != nil {
			return fmt.Errorf("verify copy of %s: %w", src, err)
		}
		return fmt.Errorf("copy of %s does not match its recorded %s checksum", src, sum.Algo)
	}
	adopted, err := Place(dst+".part", dst, sum)
	if err != nil {
		return err
	}
	rec.Adopted = rec.Adopted || adopted
	if it.Action == ActCopy {
		return removeFile(src)
	}
	return nil
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
