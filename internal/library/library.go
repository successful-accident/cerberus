// Package library owns the ISO files on disk and the state that records
// them. It covers layouts, the crash journal, adoption, aliases, pruning,
// relocation, the run lock, and the owner marker.
//
// Its central promise: cerberus deletes or overwrites only files its state
// says it wrote. Anything else in the library folder is left alone.
package library

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	_ "golang.org/x/sys/unix" // renameat2(RENAME_NOREPLACE), flock

	"github.com/successful-accident/cerberus/internal/verify"
)

// Mode is how the library is laid out.
type Mode string

const (
	// ModeDir keeps <root>/<entry-id>/<file>, with optional aliases in
	// <root>/latest/<entry-id>.iso.
	ModeDir Mode = "dir"
	// ModePVE keeps files flat in a Proxmox VE storage's ISO folder, the
	// only place PVE lists them.
	ModePVE Mode = "pve"
)

// Layout says where files live.
type Layout struct {
	Mode    Mode
	Root    string // absolute: the dir-mode root, or the PVE storage's ISO folder
	Aliases bool   // dir mode only
}

// Rel returns the library-relative path of an entry's file.
func (l Layout) Rel(entryID, filename string) string {
	if l.Mode == ModePVE {
		return filename
	}
	return filepath.Join(entryID, filename)
}

// Abs returns the absolute path for a library-relative path.
func (l Layout) Abs(rel string) string { return filepath.Join(l.Root, rel) }

// AliasPath returns where an entry's latest/ link lives, or "" when the
// layout has no aliases.
func (l Layout) AliasPath(entryID string) string {
	if l.Mode != ModeDir || !l.Aliases {
		return ""
	}
	return filepath.Join(l.Root, "latest", entryID+".iso")
}

// Entry statuses, as shown on the status screen.
const (
	StatusNew       = "new"       // selected, never synced
	StatusOK        = "ok"        // up to date
	StatusUpdated   = "updated"   // the last sync placed a new version
	StatusFailed    = "failed"    // the last sync failed; Message says why
	StatusRegressed = "regressed" // upstream's newest is older than ours
)

// FileRecord is one ISO cerberus manages.
type FileRecord struct {
	Version  string    `json:"version"`
	Rel      string    `json:"rel"`
	Algo     string    `json:"algo"`
	Hash     string    `json:"hash"`
	Size     int64     `json:"size"`
	Added    time.Time `json:"added"`
	SignedBy string    `json:"signed_by,omitempty"`
	// Adopted marks a file that was already in the library, byte for byte
	// identical, when cerberus went to place it. cerberus never deletes or
	// moves an adopted file. Pruning only drops its record.
	Adopted bool `json:"adopted,omitempty"`
}

// Checksum returns the record's expected digest.
func (r FileRecord) Checksum() verify.Checksum { return verify.Checksum{Algo: r.Algo, Hex: r.Hash} }

// KeptNote explains why a file past the keep count is still on disk.
type KeptNote struct {
	Rel    string `json:"rel"`
	Reason string `json:"reason"`
}

// EntryState is one entry's history.
type EntryState struct {
	Files      []FileRecord `json:"files"` // newest Added first
	LastCheck  time.Time    `json:"last_check,omitempty"`
	LastChange time.Time    `json:"last_change,omitempty"`
	Status     string       `json:"status,omitempty"`
	Message    string       `json:"message,omitempty"`
	Upstream   string       `json:"upstream,omitempty"` // newest version seen upstream
	Kept       []KeptNote   `json:"kept,omitempty"`
}

// Pending journals one placement in flight: the verified part file and the
// record to add once it's renamed into place.
type Pending struct {
	Entry string     `json:"entry"`
	Part  string     `json:"part"` // library-relative path of the .part file
	File  FileRecord `json:"file"`
}

// Partial is a download that may be resumed.
type Partial struct {
	Entry   string `json:"entry"`
	Version string `json:"version"`
	URL     string `json:"url"`
}

// FileMode says what relocation does with existing files.
type FileMode string

const (
	FilesMove  FileMode = "move"
	FilesCopy  FileMode = "copy"
	FilesLeave FileMode = "leave"
)

// Relocation actions.
const (
	ActRename   = "rename"    // same filesystem
	ActCopy     = "copy"      // copy, verify, rename into place, delete the source
	ActCopyKeep = "copy-keep" // copy and verify; the source stays (copy mode, or a VM uses it)
	ActSkip     = "skip"      // leave mode, or an adopted file: the record is dropped
)

// RelocItem is one file in a relocation.
type RelocItem struct {
	Entry   string `json:"entry"`
	FromRel string `json:"from_rel"`
	ToRel   string `json:"to_rel"`
	Action  string `json:"action"`
	Reason  string `json:"reason,omitempty"` // why copy-keep or skip
	Done    bool   `json:"done"`
}

// Relocation journals a move of the library between locations, so an
// interrupted move can resume.
type Relocation struct {
	FromMode Mode        `json:"from_mode"`
	FromRoot string      `json:"from_root"`
	ToMode   Mode        `json:"to_mode"`
	ToRoot   string      `json:"to_root"`
	Files    FileMode    `json:"files"`
	Items    []RelocItem `json:"items"`
}

// State is everything cerberus remembers about the library.
type State struct {
	Schema     int                    `json:"schema"` // 1
	Mode       Mode                   `json:"mode"`
	Root       string                 `json:"root"`
	Entries    map[string]*EntryState `json:"entries"`
	Pending    *Pending               `json:"pending,omitempty"`
	Partials   map[string]Partial     `json:"partials,omitempty"` // keyed by library-relative .part path
	Relocation *Relocation            `json:"relocation,omitempty"`
}

// Entry returns id's state, creating it if needed.
func (s *State) Entry(id string) *EntryState {
	if s.Entries == nil {
		s.Entries = map[string]*EntryState{}
	}
	es, ok := s.Entries[id]
	if !ok {
		es = &EntryState{Status: StatusNew}
		s.Entries[id] = es
	}
	return es
}

// LoadState reads state from path. A missing file yields an empty Schema 1
// state. An unknown Schema is an error.
func LoadState(path string) (*State, error) {
	panic("library.LoadState: not implemented (phase 1)")
}

// Save writes s to path atomically: a temp file in the same folder, fsync,
// rename, then fsync the folder. The file is mode 0644, and the folder is
// created 0755 if missing.
func (s *State) Save(path string) error {
	panic("library.State.Save: not implemented (phase 1)")
}

// ErrExists means the destination holds a different file that cerberus
// didn't write.
var ErrExists = errors.New("a different file already exists at the destination")

// Place renames the verified part file to dst without ever replacing an
// existing file, using renameat2 RENAME_NOREPLACE where the filesystem
// supports it, and otherwise a no-clobber check under the run lock. If dst
// exists with checksum sum, Place removes the part file and reports
// adopted. If dst exists and differs, it returns ErrExists and leaves both
// files. It creates dst's folder (0755) if needed.
func Place(part, dst string, sum verify.Checksum) (adopted bool, err error) {
	panic("library.Place: not implemented (phase 1)")
}

// SetAlias points l.AliasPath(entryID) at rel with a relative symlink,
// replacing any old link atomically. It does nothing when the layout has no
// aliases. It refuses to replace anything at the alias path that isn't a
// symlink.
func SetAlias(l Layout, entryID, rel string) error {
	panic("library.SetAlias: not implemented (phase 1)")
}

// RemoveAlias deletes an entry's alias if it is a symlink.
func RemoveAlias(l Layout, entryID string) error {
	panic("library.RemoveAlias: not implemented (phase 1)")
}

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
	panic("library.Prune: not implemented (phase 1)")
}

// Reconcile repairs state after a crash and returns notes for the user.
//
// If s.Pending is set, the placement is finished when its destination
// exists with the recorded size and checksum: the record is added to the
// entry if missing, and the part file is removed if still there. Otherwise
// the pending record is dropped, and the part file is kept as a resumable
// Partial if it still exists. Partials for entries that are no longer
// selected, as reported by selected(id), are deleted with their .meta
// files. Reconcile never touches a file that state doesn't name. It doesn't
// save; the caller does.
func Reconcile(l Layout, s *State, selected func(id string) bool) (notes []string, err error) {
	panic("library.Reconcile: not implemented (phase 1)")
}

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
	panic("library.PlanRelocation: not implemented (phase 1)")
}

// RunRelocation executes s.Relocation, or resumes it, one item at a time,
// marking each Done and calling save after each item. A copy goes to
// <dst>.part, is verified against the record's checksum, is renamed with
// Place, and only then is the source removed (ActCopy). When every item is
// done, it rewrites each FileRecord.Rel, drops skipped records, sets s.Mode
// and s.Root, clears s.Relocation, and calls save one last time. progress
// may be nil.
func RunRelocation(s *State, save func() error, progress func(item RelocItem, done, total int)) error {
	panic("library.RunRelocation: not implemented (phase 1)")
}

// SameFilesystem reports whether a and b, or their nearest existing
// ancestors, are on the same device.
func SameFilesystem(a, b string) (bool, error) {
	panic("library.SameFilesystem: not implemented (phase 1)")
}

// ErrLocked means another cerberus run holds the lock.
var ErrLocked = errors.New("another cerberus run is in progress")

// Lock is an exclusive run lock (flock).
type Lock struct{ f *os.File }

// AcquireLock takes the lock at path without waiting, creating the file and
// its folder if needed. It returns ErrLocked when another process holds it.
func AcquireLock(path string) (*Lock, error) {
	panic("library.AcquireLock: not implemented (phase 1)")
}

// Release drops the lock.
func (l *Lock) Release() error {
	panic("library.Lock.Release: not implemented (phase 1)")
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
	panic("library.ClaimOwner: not implemented (phase 1)")
}

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
	panic("library.DiskUsage: not implemented (phase 1)")
}
