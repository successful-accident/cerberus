package library

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/successful-accident/cerberus/internal/verify"
)

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

func sumOf(content string) verify.Checksum {
	h := sha256.Sum256([]byte(content))
	return verify.Checksum{Algo: "sha256", Hex: hex.EncodeToString(h[:])}
}

// recOf makes a record for content stored at rel, added age hours ago.
func recOf(rel, content string, ageHours int) FileRecord {
	sum := sumOf(content)
	return FileRecord{
		Version: rel, Rel: rel, Algo: sum.Algo, Hash: sum.Hex, Size: int64(len(content)),
		Added: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(-time.Duration(ageHours) * time.Hour),
	}
}
