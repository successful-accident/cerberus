package engine

import (
	"time"

	"github.com/successful-accident/cerberus/internal/catalog"
	"github.com/successful-accident/cerberus/internal/config"
	"github.com/successful-accident/cerberus/internal/library"
)

// Row is one distro on the status screen.
type Row struct {
	ID, Name  string
	Version   string // newest kept version, or ""
	LastCheck time.Time
	Status    string
	Message   string
	Upstream  string
	Size      int64 // all kept files
	Kept      int
	Notes     []string // why files past the keep count stay
}

// Rows builds the status screen's rows, in the config's order. It reads
// state without the lock, which is safe because state is written atomically.
func Rows(cfg *config.Config, cat *catalog.Catalog, st *library.State) []Row {
	var rows []Row
	for _, sel := range cfg.Selected {
		r := Row{ID: sel.ID, Name: sel.ID, Status: library.StatusNew}
		if e, ok := cat.Get(sel.ID); ok {
			r.Name = e.Name
		}
		if es := st.Entries[sel.ID]; es != nil {
			r.LastCheck, r.Message, r.Upstream = es.LastCheck, es.Message, es.Upstream
			if es.Status != "" {
				r.Status = es.Status
			}
			if k := newestKept(es, sel.Pin); k != nil {
				r.Version = k.Version
			}
			for _, f := range es.Files {
				r.Size += f.Size
			}
			r.Kept = len(es.Files)
			for _, k := range es.Kept {
				r.Notes = append(r.Notes, k.Rel+": "+k.Reason)
			}
		}
		rows = append(rows, r)
	}
	return rows
}
