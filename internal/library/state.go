package library

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// LoadState reads state from path. A missing file yields an empty Schema 1
// state. An unknown Schema is an error.
func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return &State{Schema: 1, Entries: map[string]*EntryState{}}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read state %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var s State
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parse state %s: %w", path, err)
	}
	if s.Schema != 1 {
		return nil, fmt.Errorf("state %s has unsupported schema %d", path, s.Schema)
	}
	if s.Entries == nil {
		s.Entries = map[string]*EntryState{}
	}
	return &s, nil
}

// Save writes s to path atomically: a temp file in the same folder, fsync,
// rename, then fsync the folder. The file is mode 0644, and the folder is
// created 0755 if missing.
func (s *State) Save(path string) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("encode state: %w", err)
	}
	return atomicWrite(path, append(data, '\n'))
}

// atomicWrite replaces path with data through a temp file in the same
// folder, then fsyncs the folder. The temp name starts with a dot.
func atomicWrite(path string, data []byte) (err error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".state-*.json")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err = f.Sync(); err != nil {
		return fmt.Errorf("sync %s: %w", path, err)
	}
	if err = f.Close(); err != nil {
		return fmt.Errorf("close %s: %w", path, err)
	}
	if err = os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return fmt.Errorf("sync folder %s: %w", dir, err)
	}
	return nil
}
