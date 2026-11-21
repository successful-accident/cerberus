package library

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestLoadStateMissing(t *testing.T) {
	s, err := LoadState(filepath.Join(t.TempDir(), "nope", "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	if s.Schema != 1 || s.Entries == nil || len(s.Entries) != 0 {
		t.Fatalf("got %+v", s)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state", "sub")
	path := filepath.Join(dir, "state.json")
	s := &State{Schema: 1, Mode: ModeDir, Root: "/srv/isos", Entries: map[string]*EntryState{}}
	es := s.Entry("alpine")
	es.Files = []FileRecord{recOf("alpine/a.iso", "aaa", 0)}
	es.Files[0].Added = es.Files[0].Added.UTC()
	es.LastCheck = time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	es.Kept = []KeptNote{{Rel: "alpine/old.iso", Reason: "in use by VM 105"}}
	s.Pending = &Pending{Entry: "alpine", Part: "alpine/b.iso.part", File: recOf("alpine/b.iso", "bbb", 1)}
	s.Partials = map[string]Partial{"alpine/c.iso.part": {Entry: "alpine", Version: "3", URL: "https://x/c.iso"}}

	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, s) {
		t.Fatalf("round trip differs:\n got %+v\nwant %+v", got, s)
	}
	fi, err := os.Stat(path)
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode: %v %v", fi, err)
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Fatalf("temp files left behind: %v", ents)
	}
	// A second save replaces the first.
	s.Mode = ModePVE
	if err := s.Save(path); err != nil {
		t.Fatal(err)
	}
	if got, _ := LoadState(path); got.Mode != ModePVE {
		t.Fatal("second save lost")
	}
}

func TestLoadStateRejects(t *testing.T) {
	for name, body := range map[string]string{
		"unknown field":  `{"schema":1,"entries":{},"bogus":true}`,
		"other schema":   `{"schema":2,"entries":{}}`,
		"missing schema": `{"entries":{}}`,
		"not json":       `nope`,
		"file outside":   `{"schema":1,"entries":{"a":{"files":[{"version":"1","rel":"../victim.iso","algo":"sha256","hash":"","size":0,"added":"2026-01-01T00:00:00Z"}]}}}`,
		"absolute file":  `{"schema":1,"entries":{"a":{"files":[{"version":"1","rel":"/etc/passwd","algo":"sha256","hash":"","size":0,"added":"2026-01-01T00:00:00Z"}]}}}`,
		"kept outside":   `{"schema":1,"entries":{"a":{"files":[],"kept":[{"rel":"../x.iso","reason":"r"}]}}}`,
		"pending part":   `{"schema":1,"entries":{},"pending":{"entry":"a","part":"../x.part","file":{"version":"1","rel":"a/x.iso","algo":"sha256","hash":"","size":0,"added":"2026-01-01T00:00:00Z"}}}`,
		"partial key":    `{"schema":1,"entries":{},"partials":{"../x.iso.part":{"entry":"a","version":"1","url":""}}}`,
		"move item":      `{"schema":1,"entries":{},"relocation":{"from_mode":"dir","from_root":"/a","to_mode":"dir","to_root":"/b","files":"move","items":[{"entry":"a","from_rel":"a/x.iso","to_rel":"../x.iso","action":"rename","done":false}]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "state.json")
			write(t, p, body)
			if _, err := LoadState(p); err == nil {
				t.Fatal("want an error")
			} else if !strings.Contains(err.Error(), p) {
				t.Fatalf("error lacks the path: %v", err)
			}
		})
	}
}
