package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/successful-accident/cerberus/internal/download"
	"github.com/successful-accident/cerberus/internal/host"
	"github.com/successful-accident/cerberus/internal/library"
)

// Target is where the library should live.
type Target struct {
	Mode    library.Mode
	Dir     string // dir mode: an absolute folder
	Storage string // pve mode: the storage ID
}

func (e *Env) targetLayout(ctx context.Context, t Target) (library.Layout, error) {
	if t.Mode == library.ModePVE {
		return e.pveLayout(ctx, t.Storage)
	}
	if !filepath.IsAbs(t.Dir) {
		return library.Layout{}, fmt.Errorf("%q must be an absolute path", t.Dir)
	}
	return library.Layout{Mode: library.ModeDir, Root: filepath.Clean(t.Dir), Aliases: e.Config.Aliases}, nil
}

// Relocate moves the library to t, or finishes an unfinished move to t.
// It saves the config as soon as the move is planned, so an interruption
// leaves config and state pointing at the same unfinished move, and running
// it again resumes. Copies must leave the free-space reserve on the target:
// a move whose copies don't fit is refused before it starts, and each copy
// checks again. Into a Proxmox storage, every file waits for a fresh check
// that PVE reports the storage enabled and active. A failed check stops the
// move with its journal intact. progress may be nil.
func (s *Session) Relocate(ctx context.Context, t Target, files library.FileMode, takeOver bool,
	progress func(item library.RelocItem, done, total int)) error {
	env, st := s.Env, s.State
	to, err := env.targetLayout(ctx, t)
	if err != nil {
		return err
	}
	from := s.Layout
	if st.Relocation != nil {
		r := st.Relocation
		if r.ToRoot != to.Root || r.ToMode != to.Mode {
			return fmt.Errorf("%w to %s; finish that one first", ErrRelocating, r.ToRoot)
		}
		from = library.Layout{Mode: r.FromMode, Root: r.FromRoot, Aliases: env.Config.Aliases}
	} else {
		if from.Root == to.Root && from.Mode == to.Mode {
			return fmt.Errorf("the library is already at %s", to.Root)
		}
		if to.Mode == library.ModeDir {
			if err := os.MkdirAll(to.Root, 0o755); err != nil {
				return err
			}
		}
		if err := library.ClaimOwner(to.Root, env.machineID(), takeOver); err != nil {
			return squashHint(err, to, t.Storage)
		}
		if st.Root == "" || len(st.Entries) == 0 {
			// Nothing has been placed yet, so there's nothing to move.
			st.Mode, st.Root = to.Mode, to.Root
			if err := s.Save(); err != nil {
				return err
			}
			s.Layout = to
			return s.pointConfigAt(t)
		}
		protect, err := s.protector(from, env.Config.Storage)
		if err != nil {
			return err
		}
		plan, err := library.PlanRelocation(st, from, to, files, protect)
		if err != nil {
			return err
		}
		var copies int64
		for _, it := range plan.Items {
			if it.Action == library.ActCopy || it.Action == library.ActCopyKeep {
				for _, f := range st.Entries[it.Entry].Files {
					if f.Rel == it.FromRel {
						copies += f.Size
					}
				}
			}
		}
		if err := s.checkSpace(to, copies); err != nil {
			return err
		}
		st.Relocation = plan
		if err := s.Save(); err != nil {
			return err
		}
		if err := s.pointConfigAt(t); err != nil {
			return err
		}
	}
	for _, it := range st.Relocation.Items {
		if it.Reason != "" && !it.Done {
			env.logf("%s: %s, so it's copied and the original stays", it.FromRel, it.Reason)
		}
	}
	before := func(it library.RelocItem, rec library.FileRecord) error {
		if to.Mode == library.ModePVE {
			if _, err := host.PVEStorageReady(ctx, env.Run, env.Host.Node, t.Storage); err != nil {
				return err
			}
		}
		if it.Action == library.ActCopy || it.Action == library.ActCopyKeep {
			return s.checkSpace(to, rec.Size)
		}
		return nil
	}
	if err := library.RunRelocation(st, s.Save, before, progress); err != nil {
		return squashHint(err, to, t.Storage)
	}
	s.Layout = to
	for id, es := range st.Entries {
		_ = library.RemoveAlias(from, id)
		if len(es.Files) > 0 {
			if err := library.SetAlias(to, id, es.Files[0].Rel); err != nil {
				env.logf("%s: couldn't update the latest/ link: %v", id, err)
			}
		}
	}
	// cerberus no longer manages the old location. Drop its owner marker, so
	// another host can use the folder later. In dir mode, also drop the
	// folders the move emptied: os.Remove only removes an empty folder, so
	// files left there in copy or leave mode stay put.
	// The same folder in the other mode is still the library.
	if filepath.Clean(from.Root) != filepath.Clean(to.Root) {
		_ = os.Remove(filepath.Join(from.Root, library.OwnerFile))
	}
	if from.Mode == library.ModeDir {
		for id := range st.Entries {
			_ = os.Remove(filepath.Join(from.Root, id))
		}
		_ = os.Remove(filepath.Join(from.Root, "latest"))
	}
	return nil
}

// checkSpace refuses copying need bytes into l when it would eat into the
// free-space reserve.
func (s *Session) checkSpace(l library.Layout, need int64) error {
	if need <= 0 {
		return nil
	}
	r := s.Env.Config.Reserve
	return download.CheckSpace(l.Root, need, r.Percent, r.MinBytes())
}

func (s *Session) pointConfigAt(t Target) error {
	c := s.Env.Config
	c.Mode, c.Dir, c.Storage = t.Mode, "", ""
	if t.Mode == library.ModePVE {
		c.Storage = t.Storage
	} else {
		c.Dir = filepath.Clean(t.Dir)
	}
	return c.Save(s.Env.Paths.Config)
}

// Forget deselects nothing itself, but drops ids from state. With
// deleteFiles, it also deletes the files cerberus downloaded for them,
// except adopted files and files a VM uses. It returns what it deleted.
func (s *Session) Forget(ids []string, deleteFiles bool) ([]string, error) {
	protect, err := s.protector(s.Layout, s.Env.Config.Storage)
	if err != nil {
		return nil, err
	}
	var deleted []string
	for _, id := range ids {
		es, ok := s.State.Entries[id]
		if !ok {
			continue
		}
		if deleteFiles {
			es.Files = slices.DeleteFunc(es.Files, func(f library.FileRecord) bool {
				if f.Adopted || protect(f.Rel) != "" {
					return false
				}
				if err := os.Remove(s.Layout.Abs(f.Rel)); err != nil && !os.IsNotExist(err) {
					s.Env.logf("%s: couldn't delete %s: %v", id, f.Rel, err)
					return false
				}
				deleted = append(deleted, f.Rel)
				return true
			})
			for p, info := range s.State.Partials {
				if info.Entry == id {
					s.dropPartial(p)
				}
			}
			if len(es.Files) > 0 {
				var kept []string
				for _, f := range es.Files {
					kept = append(kept, f.Rel)
				}
				s.Env.logf("%s: kept %s (adopted, or in use by a VM)", id, strings.Join(kept, ", "))
			}
		}
		_ = library.RemoveAlias(s.Layout, id)
		delete(s.State.Entries, id)
	}
	return deleted, s.Save()
}
