// Package library owns the ISO files on disk and the state that records
// them. It covers layouts, the crash journal, adoption, aliases, pruning,
// relocation, the run lock, and the owner marker.
//
// Its central promise: cerberus deletes or overwrites only files its state
// says it wrote. Anything else in the library folder is left alone.
package library

import (
	"path/filepath"
	"time"

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
	// Copying marks a copy whose <dst>.part cerberus has started to write.
	// It is saved before the first byte, so on resume the part file is
	// known to be cerberus's, and a destination with no part file left is
	// cerberus's own placed copy, not a file that was already there.
	Copying bool `json:"copying,omitempty"`
	Done    bool `json:"done"`
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
