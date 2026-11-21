// Package engine runs cerberus. It opens the library under the run lock,
// syncs each selected distro (resolve, download, verify, place, prune),
// moves the library, and reports what happened. It enforces the Rules in
// PLAN.md by ordering the packages' operations: nothing is pruned before its
// replacement is verified and placed, and every write to a Proxmox storage
// follows a fresh check that PVE reports it active.
package engine

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/successful-accident/cerberus/internal/catalog"
	"github.com/successful-accident/cerberus/internal/config"
	"github.com/successful-accident/cerberus/internal/download"
	"github.com/successful-accident/cerberus/internal/host"
	"github.com/successful-accident/cerberus/internal/library"
	"github.com/successful-accident/cerberus/internal/notify"
	"github.com/successful-accident/cerberus/internal/resolve"
	"github.com/successful-accident/cerberus/internal/verify"
)

// Env is everything a run needs from outside the library.
type Env struct {
	Config   *config.Config
	Paths    config.Paths
	Catalog  *catalog.Catalog
	Host     *host.Info
	HostRoot string // "/" in production; a fake tree in tests
	Run      host.Runner
	Client   *download.Client
	Log      io.Writer                          // human-readable lines; nil means none
	Progress func(id string, done, total int64) // download progress; may be nil
	Now      func() time.Time                   // nil means time.Now
}

func (e *Env) now() time.Time {
	if e.Now != nil {
		return e.Now()
	}
	return time.Now()
}

func (e *Env) logf(format string, args ...any) {
	if e.Log != nil {
		fmt.Fprintf(e.Log, format+"\n", args...)
	}
}

func (e *Env) machineID() string {
	if e.Host.MachineID != "" {
		return e.Host.MachineID
	}
	return "host:" + e.Host.Hostname
}

// ErrNeedRoot means Proxmox mode was used without root.
var ErrNeedRoot = errors.New("pve mode needs root, because PVE's storage folders and VM configs are root-only")

// ErrRelocating means a library move is unfinished.
var ErrRelocating = errors.New("a library move is unfinished")

// Layout works out where the library lives now. In PVE mode it needs root
// and asks PVE whether the storage is enabled and active.
func (e *Env) Layout(ctx context.Context) (library.Layout, error) {
	if e.Config.Mode == library.ModePVE {
		return e.pveLayout(ctx, e.Config.Storage)
	}
	return library.Layout{Mode: library.ModeDir, Root: filepath.Clean(e.Config.Dir), Aliases: e.Config.Aliases}, nil
}

func (e *Env) pveLayout(ctx context.Context, storage string) (library.Layout, error) {
	if !e.Host.Root {
		return library.Layout{}, ErrNeedRoot
	}
	if _, err := host.PVEStorageReady(ctx, e.Run, e.Host.Node, storage); err != nil {
		return library.Layout{}, err
	}
	dir, err := host.PVEISODir(ctx, e.Run, storage)
	if err != nil {
		return library.Layout{}, err
	}
	return library.Layout{Mode: library.ModePVE, Root: dir}, nil
}

// Session is the library opened for writing, under the run lock.
type Session struct {
	Env    *Env
	Layout library.Layout
	State  *library.State
	Notes  []string // what Reconcile repaired
	lock   *library.Lock
}

// OpenOptions adjust Open.
type OpenOptions struct {
	// TakeOver claims a library another host has marked as its own.
	TakeOver bool
	// Resume allows an unfinished move, so Relocate can finish it.
	Resume bool
}

// Open takes the run lock, loads state, checks that the config and state
// agree on where the library is, claims the owner marker, and reconciles
// work a crash interrupted.
func Open(ctx context.Context, env *Env, o OpenOptions) (*Session, error) {
	lock, err := library.AcquireLock(env.Paths.Lock())
	if err != nil {
		return nil, err
	}
	s := &Session{Env: env, lock: lock}
	if err := s.open(ctx, o); err != nil {
		lock.Release()
		return nil, err
	}
	return s, nil
}

func (s *Session) open(ctx context.Context, o OpenOptions) error {
	env := s.Env
	st, err := library.LoadState(env.Paths.State())
	if err != nil {
		return err
	}
	s.State = st
	if st.Relocation != nil {
		if o.Resume {
			return nil
		}
		return fmt.Errorf("%w: run `cerberus location set` with the same target to finish moving to %s", ErrRelocating, st.Relocation.ToRoot)
	}
	if s.Layout, err = env.Layout(ctx); err != nil {
		return err
	}
	if st.Root != "" && (st.Root != s.Layout.Root || st.Mode != s.Layout.Mode) {
		return fmt.Errorf("the config points at %s, but the library is at %s; use `cerberus location set` to move it", s.Layout.Root, st.Root)
	}
	if s.Layout.Mode == library.ModeDir {
		if err := os.MkdirAll(s.Layout.Root, 0o755); err != nil {
			return err
		}
	}
	if err := library.ClaimOwner(s.Layout.Root, env.machineID(), o.TakeOver); err != nil {
		return err
	}
	st.Mode, st.Root = s.Layout.Mode, s.Layout.Root
	if s.Notes, err = library.Reconcile(s.Layout, st, func(id string) bool { return env.Config.Selection(id) != nil }); err != nil {
		return err
	}
	return s.Save()
}

// Save writes the state.
func (s *Session) Save() error { return s.State.Save(s.Env.Paths.State()) }

// Close releases the run lock.
func (s *Session) Close() error { return s.lock.Release() }

// Status values in reports beyond library's.
const (
	// StatusAvailable means a newer version exists; only Check reports it.
	StatusAvailable = "available"
	// StatusSkipped means the run stopped before reaching the distro.
	StatusSkipped = "skipped"
)

// Result is what happened to one distro.
type Result struct {
	ID, Name string
	Status   string // a library.Status* value, StatusAvailable or StatusSkipped
	From     string // the newest version kept before the run
	To       string // the version kept after the run, or upstream's newest
	Message  string
}

// Report is what happened in one run.
type Report struct {
	Results []Result
	Stopped error // set when the run stopped early, for example a full disk
}

// Changed reports whether anything happened worth an alert.
func (r *Report) Changed() bool {
	if r.Stopped != nil {
		return true
	}
	for _, res := range r.Results {
		switch res.Status {
		case library.StatusUpdated, library.StatusFailed, library.StatusRegressed:
			return true
		}
	}
	return false
}

// Message summarizes the report for ntfy.
func (r *Report) Message(hostname string) notify.Message {
	var lines []string
	bad := r.Stopped != nil
	for _, res := range r.Results {
		switch res.Status {
		case library.StatusUpdated:
			from := res.From
			if from == "" {
				from = "new"
			}
			lines = append(lines, fmt.Sprintf("%s: %s → %s", res.Name, from, res.To))
		case library.StatusFailed, library.StatusRegressed:
			bad = true
			lines = append(lines, fmt.Sprintf("%s: %s", res.Name, res.Message))
		}
	}
	if r.Stopped != nil {
		lines = append(lines, "The run stopped early: "+r.Stopped.Error())
	}
	m := notify.Message{Title: hostname + ": cerberus", Body: strings.Join(lines, "\n"), Tags: []string{"white_check_mark"}}
	if bad {
		m.Tags, m.Priority = []string{"warning"}, 4
	}
	return m
}

// job is one distro's resolution.
type job struct {
	sel   config.Selection
	entry *catalog.Entry
	keys  *verify.Keyring
	rel   *resolve.Release
	err   error
}

// selections returns the selections for ids, or all of them.
func (e *Env) selections(ids []string) ([]config.Selection, error) {
	if len(ids) == 0 {
		return e.Config.Selected, nil
	}
	var out []config.Selection
	for _, id := range ids {
		sel := e.Config.Selection(id)
		if sel == nil {
			return nil, fmt.Errorf("%s isn't selected; add it with `cerberus add %s`", id, id)
		}
		out = append(out, *sel)
	}
	return out, nil
}

// resolveAll resolves the selections eight at a time.
func (e *Env) resolveAll(ctx context.Context, sels []config.Selection) []*job {
	jobs := make([]*job, len(sels))
	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for i, sel := range sels {
		j := &job{sel: sel}
		jobs[i] = j
		ent, ok := e.Catalog.Get(sel.ID)
		if !ok {
			j.err = fmt.Errorf("%s isn't in the catalog", sel.ID)
			continue
		}
		j.entry = ent
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			j.keys, j.rel, j.err = e.resolveOne(ctx, ent, sel)
		}()
	}
	wg.Wait()
	return jobs
}

func (e *Env) resolveOne(ctx context.Context, ent *catalog.Entry, sel config.Selection) (*verify.Keyring, *resolve.Release, error) {
	opt := resolve.Options{Arch: e.Config.Arch, Pin: sel.Pin}
	var kr *verify.Keyring
	if len(ent.Keys) > 0 {
		keys, err := e.Catalog.KeysFor(ent)
		if err != nil {
			return nil, nil, err
		}
		if kr, err = verify.NewKeyring(keys, ent.Fingerprints); err != nil {
			return nil, nil, fmt.Errorf("%s: %w", ent.ID, err)
		}
		opt.Verifier = kr
	}
	rel, err := resolve.Resolve(ctx, e.Client, ent, opt)
	return kr, rel, err
}

// newestKept returns the highest kept version matching pin, or nil.
func newestKept(es *library.EntryState, pin string) *library.FileRecord {
	if es == nil {
		return nil
	}
	var best *library.FileRecord
	for i := range es.Files {
		f := &es.Files[i]
		if resolve.MatchesPin(f.Version, pin) && (best == nil || resolve.CompareVersions(f.Version, best.Version) > 0) {
			best = f
		}
	}
	return best
}

// Check resolves the selected distros, or only ids, and reports what a sync
// would do. It takes no lock and writes nothing.
func Check(ctx context.Context, env *Env, st *library.State, ids []string) (*Report, error) {
	sels, err := env.selections(ids)
	if err != nil {
		return nil, err
	}
	rep := &Report{}
	for _, j := range env.resolveAll(ctx, sels) {
		res := Result{ID: j.sel.ID, Name: j.sel.ID}
		if j.entry != nil {
			res.Name = j.entry.Name
		}
		kept := newestKept(st.Entries[j.sel.ID], j.sel.Pin)
		if kept != nil {
			res.From = kept.Version
		}
		switch {
		case j.err != nil:
			res.Status, res.Message = library.StatusFailed, j.err.Error()
		case kept == nil:
			res.Status, res.To = StatusAvailable, j.rel.Version
		default:
			res.To = j.rel.Version
			switch c := resolve.CompareVersions(j.rel.Version, kept.Version); {
			case c == 0:
				res.Status = library.StatusOK
			case c > 0:
				res.Status = StatusAvailable
			default:
				res.Status = library.StatusRegressed
				res.Message = fmt.Sprintf("upstream's newest is %s, older than your %s", j.rel.Version, kept.Version)
			}
		}
		rep.Results = append(rep.Results, res)
	}
	return rep, nil
}

// stopError marks a failure that ends the whole run.
type stopError struct{ error }

func (e stopError) Unwrap() error { return e.error }

// Sync updates the selected distros, or only ids. It resolves them all
// first, eight at a time, then updates them one at a time, saving state
// after each.
func (s *Session) Sync(ctx context.Context, ids []string) (*Report, error) {
	env := s.Env
	sels, err := env.selections(ids)
	if err != nil {
		return nil, err
	}
	protect, err := s.protector(s.Layout, env.Config.Storage)
	if err != nil {
		return nil, err
	}
	jobs := env.resolveAll(ctx, sels)
	rep := &Report{}
	for _, j := range jobs {
		if rep.Stopped == nil && ctx.Err() != nil {
			rep.Stopped = ctx.Err()
		}
		if rep.Stopped != nil {
			rep.Results = append(rep.Results, Result{ID: j.sel.ID, Name: j.sel.ID, Status: StatusSkipped})
			continue
		}
		rep.Results = append(rep.Results, s.syncOne(ctx, j, protect, rep))
		if err := s.Save(); err != nil {
			return rep, err
		}
	}
	return rep, nil
}

// protector returns the ProtectFunc for a layout: in PVE mode, ISOs that a
// VM config on storage references are protected.
func (s *Session) protector(l library.Layout, storage string) (library.ProtectFunc, error) {
	if l.Mode != library.ModePVE {
		return func(string) string { return "" }, nil
	}
	refs, err := host.VMISORefs(s.Env.HostRoot, storage)
	if err != nil {
		return nil, fmt.Errorf("reading VM configs: %w", err)
	}
	return func(rel string) string {
		if vms := refs[filepath.Base(rel)]; len(vms) > 0 {
			return "in use by VM " + strings.Join(vms, ", ")
		}
		return ""
	}, nil
}

func (s *Session) syncOne(ctx context.Context, j *job, protect library.ProtectFunc, rep *Report) Result {
	env := s.Env
	id := j.sel.ID
	res := Result{ID: id, Name: id}
	if j.entry != nil {
		res.Name = j.entry.Name
	}
	es := s.State.Entry(id)
	es.LastCheck = env.now()
	s.forgetMissing(id, es)
	kept := newestKept(es, j.sel.Pin)
	if kept != nil {
		res.From, res.To = kept.Version, kept.Version
	}
	finish := func(status, msg string) Result {
		res.Status, res.Message = status, msg
		es.Status, es.Message = status, msg
		if msg != "" {
			env.logf("%s: %s", id, msg)
		}
		return res
	}
	if j.err != nil {
		return finish(library.StatusFailed, j.err.Error())
	}
	es.Upstream = j.rel.Version
	if kept != nil {
		switch c := resolve.CompareVersions(j.rel.Version, kept.Version); {
		case c == 0:
			env.logf("%s: %s is current", id, kept.Version)
			return finish(library.StatusOK, "")
		case c < 0:
			return finish(library.StatusRegressed, fmt.Sprintf("upstream's newest is %s, older than your %s; keeping yours", j.rel.Version, kept.Version))
		}
	}
	rec, err := s.fetchAndPlace(ctx, j, es)
	if err != nil {
		var stop stopError
		if errors.As(err, &stop) {
			rep.Stopped = stop.error
		}
		return finish(library.StatusFailed, err.Error())
	}
	res.To = rec.Version
	if err := library.SetAlias(s.Layout, id, rec.Rel); err != nil {
		env.logf("%s: couldn't update the latest/ link: %v", id, err)
	}
	removed, err := library.Prune(s.Layout, es, env.Config.KeepFor(id), protect)
	for _, r := range removed {
		env.logf("%s: removed %s", id, r.Version)
	}
	for _, k := range es.Kept {
		env.logf("%s: kept %s: %s", id, k.Rel, k.Reason)
	}
	es.LastChange = env.now()
	msg := ""
	if rec.Adopted {
		msg = "the identical file was already in the library, so cerberus adopted it"
	}
	if err != nil {
		msg = "placed, but pruning stopped: " + err.Error()
	}
	env.logf("%s: updated to %s", id, rec.Version)
	return finish(library.StatusUpdated, msg)
}

// forgetMissing drops records whose files are gone, so the distro is
// downloaded again.
func (s *Session) forgetMissing(id string, es *library.EntryState) {
	es.Files = slices.DeleteFunc(es.Files, func(f library.FileRecord) bool {
		if _, err := os.Stat(s.Layout.Abs(f.Rel)); errors.Is(err, fs.ErrNotExist) {
			s.Env.logf("%s: %s is gone from the library, so cerberus forgot it", id, f.Version)
			return true
		}
		return false
	})
}

// fetchAndPlace downloads, verifies and places one release, journaling each
// step in state.
func (s *Session) fetchAndPlace(ctx context.Context, j *job, es *library.EntryState) (library.FileRecord, error) {
	env, st, l := s.Env, s.State, s.Layout
	rel, id := j.rel, j.sel.ID
	if !catalog.ValidFilename(rel.Filename) {
		return library.FileRecord{}, fmt.Errorf("refusing unsafe file name %q", rel.Filename)
	}
	relPath := l.Rel(id, rel.Filename)
	dst := l.Abs(relPath)
	partRel := relPath + ".part"
	part := l.Abs(partRel)
	if st.Partials == nil {
		st.Partials = map[string]library.Partial{}
	}
	for p, info := range st.Partials {
		if info.Entry == id && p != partRel {
			s.dropPartial(p)
		}
	}
	if l.Mode == library.ModePVE {
		if _, err := host.PVEStorageReady(ctx, env.Run, env.Host.Node, env.Config.Storage); err != nil {
			return library.FileRecord{}, stopError{err}
		}
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return library.FileRecord{}, err
	}
	size, err := env.Client.Size(ctx, rel.URL)
	if err != nil {
		size = -1
	}
	need := size
	if fi, err := os.Stat(part); err == nil && size > 0 {
		need = max(size-fi.Size(), 0)
	}
	if err := download.CheckSpace(filepath.Dir(dst), need, env.Config.Reserve.Percent, env.Config.Reserve.MinBytes()); err != nil {
		return library.FileRecord{}, err
	}
	st.Partials[partRel] = library.Partial{Entry: id, Version: rel.Version, URL: rel.URL}
	if err := s.Save(); err != nil {
		return library.FileRecord{}, err
	}
	env.logf("%s: downloading %s (%s)", id, rel.Version, HumanSize(size))
	var progress download.Progress
	if env.Progress != nil {
		progress = func(done, total int64) { env.Progress(id, done, total) }
	}
	if _, err := env.Client.Fetch(ctx, rel.URL, part, progress); err != nil {
		if errors.Is(err, download.ErrNoSpace) {
			s.dropPartial(partRel)
			return library.FileRecord{}, stopError{err}
		}
		return library.FileRecord{}, fmt.Errorf("download failed; the next run resumes it: %w", err)
	}
	ok, err := rel.Checksum.MatchFile(part)
	if err != nil {
		return library.FileRecord{}, err
	}
	if !ok {
		s.dropPartial(partRel)
		return library.FileRecord{}, fmt.Errorf("checksum mismatch for %s %s, so the download was deleted", rel.Filename, rel.Checksum.Algo)
	}
	signedBy := rel.SignedBy
	if rel.ISOSignatureURL != "" {
		fp, err := s.checkISOSignature(ctx, j, part)
		if err != nil {
			s.dropPartial(partRel)
			return library.FileRecord{}, fmt.Errorf("signature check failed for %s, so the download was deleted: %w", rel.Filename, err)
		}
		signedBy = fp
	}
	fi, err := os.Stat(part)
	if err != nil {
		return library.FileRecord{}, err
	}
	rec := library.FileRecord{Version: rel.Version, Rel: relPath, Algo: rel.Checksum.Algo, Hash: rel.Checksum.Hex,
		Size: fi.Size(), Added: env.now(), SignedBy: signedBy}
	st.Pending = &library.Pending{Entry: id, Part: partRel, File: rec}
	delete(st.Partials, partRel)
	if err := s.Save(); err != nil {
		return library.FileRecord{}, err
	}
	adopted, err := library.Place(part, dst, rel.Checksum)
	if err != nil {
		st.Pending = nil
		removeQuietly(part, part+".meta")
		if errors.Is(err, library.ErrExists) {
			err = fmt.Errorf("%s is already in the library and differs from the download; cerberus won't overwrite a file it didn't write", rel.Filename)
		}
		return library.FileRecord{}, errors.Join(err, s.Save())
	}
	rec.Adopted = adopted
	es.Files = slices.DeleteFunc(es.Files, func(f library.FileRecord) bool { return f.Rel == rec.Rel })
	es.Files = append([]library.FileRecord{rec}, es.Files...)
	st.Pending = nil
	return rec, s.Save()
}

func (s *Session) checkISOSignature(ctx context.Context, j *job, part string) (string, error) {
	if j.keys == nil {
		return "", errors.New("the entry declares an ISO signature but has no keys")
	}
	doc, err := s.Env.Client.Get(ctx, j.rel.ISOSignatureURL)
	if err != nil {
		return "", err
	}
	return j.keys.VerifyDetachedFile(part, doc.Body)
}

// dropPartial deletes a partial download cerberus recorded, and its record.
func (s *Session) dropPartial(partRel string) {
	p := s.Layout.Abs(partRel)
	removeQuietly(p, p+".meta")
	delete(s.State.Partials, partRel)
}

func removeQuietly(paths ...string) {
	for _, p := range paths {
		_ = os.Remove(p)
	}
}

// HumanSize formats a byte count in decimal units, like "812 MB" or
// "3.1 GB". A negative count is "unknown size".
func HumanSize(n int64) string {
	switch {
	case n < 0:
		return "unknown size"
	case n >= 1e12:
		return fmt.Sprintf("%.1f TB", float64(n)/1e12)
	case n >= 1e9:
		return fmt.Sprintf("%.1f GB", float64(n)/1e9)
	case n >= 1e6:
		return fmt.Sprintf("%.0f MB", float64(n)/1e6)
	case n >= 1e3:
		return fmt.Sprintf("%.0f kB", float64(n)/1e3)
	}
	return fmt.Sprintf("%d B", n)
}
