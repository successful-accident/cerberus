package verify

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	h256a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	h256b = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

var h512 = strings.Repeat("c", 128)

func TestParseChecksums(t *testing.T) {
	doc := strings.Join([]string{
		"-----BEGIN PGP SIGNED MESSAGE-----",
		"Hash: SHA256",
		"",
		"# AlmaLinux-10.3-x86_64-minimal.iso: 2048 bytes",
		"SHA256 (AlmaLinux-10.3-x86_64-minimal.iso) = " + strings.ToUpper(h256a),
		h256b + "  debian-13.7.0-amd64-netinst.iso\r",
		h256a + " *ubuntu-26.04.1-live-server-amd64.iso",
		h512 + "  ./iso/archlinux-2026.11.01-x86_64.iso",
		"SHA512 (both.iso) = " + h512,
		"SHA256 (both.iso) = " + h256a,
		"deadbeef  too-short.iso",
		h256b,
	}, "\n")
	got := ParseChecksums([]byte(doc))
	want := map[string]Checksum{
		"AlmaLinux-10.3-x86_64-minimal.iso":    {"sha256", h256a},
		"debian-13.7.0-amd64-netinst.iso":      {"sha256", h256b},
		"ubuntu-26.04.1-live-server-amd64.iso": {"sha256", h256a},
		"iso/archlinux-2026.11.01-x86_64.iso":  {"sha512", h512},
		"archlinux-2026.11.01-x86_64.iso":      {"sha512", h512},
		"both.iso":                             {"sha512", h512},
		"":                                     {"sha256", h256b},
	}
	if len(got) != len(want) {
		t.Errorf("got %d entries, want %d: %v", len(got), len(want), got)
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%q: got %v, want %v", name, got[name], w)
		}
	}
}

func TestChecksumValid(t *testing.T) {
	for _, c := range []struct {
		sum  Checksum
		want bool
	}{
		{Checksum{"sha256", h256a}, true},
		{Checksum{"sha512", h512}, true},
		{Checksum{"sha256", strings.ToUpper(h256a)}, false},
		{Checksum{"sha256", h512}, false},
		{Checksum{"md5", "d41d8cd98f00b204e9800998ecf8427e"}, false},
	} {
		if got := c.sum.Valid(); got != c.want {
			t.Errorf("%v.Valid() = %v, want %v", c.sum, got, c.want)
		}
	}
}

func TestHashFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "x.iso")
	if err := os.WriteFile(p, []byte("abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Known digest of "abc".
	sum := Checksum{"sha256", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}
	ok, err := sum.MatchFile(p)
	if err != nil || !ok {
		t.Fatalf("MatchFile = %v, %v; want true, nil", ok, err)
	}
	if _, err := HashFile(p, "md5"); err == nil {
		t.Error("HashFile accepted md5")
	}
}
