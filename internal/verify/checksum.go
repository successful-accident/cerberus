// Package verify checks downloads: checksum files in their common formats,
// file digests, and OpenPGP signatures against pinned keys.
package verify

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"regexp"
	"strings"
)

// Checksum is an expected digest.
type Checksum struct {
	Algo string // "sha256" or "sha512"
	Hex  string // lowercase hex
}

// Valid reports whether Algo is known and Hex is lowercase hex of its
// length.
func (c Checksum) Valid() bool {
	switch c.Algo {
	case "sha256":
		return isLowerHex(c.Hex, 64)
	case "sha512":
		return isLowerHex(c.Hex, 128)
	}
	return false
}

func (c Checksum) String() string { return c.Algo + ":" + c.Hex }

// MatchFile reports whether the file at p has this checksum.
func (c Checksum) MatchFile(p string) (bool, error) {
	got, err := HashFile(p, c.Algo)
	if err != nil {
		return false, err
	}
	return got == c.Hex, nil
}

var (
	bsdLine  = regexp.MustCompile(`^(SHA256|SHA512) ?\((.+)\) ?= ?([0-9A-Fa-f]+)$`)
	gnuLine  = regexp.MustCompile(`^([0-9A-Fa-f]{64}|[0-9A-Fa-f]{128})[ \t]+\*?(\S.*)$`)
	bareLine = regexp.MustCompile(`^([0-9A-Fa-f]{64}|[0-9A-Fa-f]{128})$`)
)

// ParseChecksums reads checksum lines in GNU form ("<hex>  <name>" or
// "<hex> *<name>"), BSD form ("SHA256 (<name>) = <hex>"), or bare form (a
// lone hex digest, stored under the name ""). It ignores every other line,
// so comments and PGP armor pass through harmlessly. The algorithm comes from
// the BSD tag or the digest length. Names lose a leading "./", and a name
// with a directory is also stored under its base name unless that's taken.
// When a name appears twice, sha512 beats sha256; otherwise the later line
// wins.
func ParseChecksums(doc []byte) map[string]Checksum {
	out := map[string]Checksum{}
	put := func(name string, c Checksum) {
		if old, ok := out[name]; ok && old.Algo == "sha512" && c.Algo == "sha256" {
			return
		}
		out[name] = c
	}
	sc := bufio.NewScanner(bytes.NewReader(doc))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		var algo, name, digest string
		if m := bsdLine.FindStringSubmatch(line); m != nil {
			algo, name, digest = strings.ToLower(m[1]), m[2], m[3]
		} else if m := gnuLine.FindStringSubmatch(line); m != nil {
			digest, name = m[1], strings.TrimSpace(m[2])
		} else if m := bareLine.FindStringSubmatch(line); m != nil {
			digest = m[1]
		} else {
			continue
		}
		if algo == "" {
			algo = map[int]string{64: "sha256", 128: "sha512"}[len(digest)]
		}
		c := Checksum{Algo: algo, Hex: strings.ToLower(digest)}
		if !c.Valid() {
			continue
		}
		name = strings.TrimPrefix(name, "./")
		put(name, c)
		if base := path.Base(name); name != "" && base != name {
			if _, taken := out[base]; !taken {
				put(base, c)
			}
		}
	}
	return out
}

// NewHash returns a hash for "sha256" or "sha512".
func NewHash(algo string) (hash.Hash, error) {
	switch algo {
	case "sha256":
		return sha256.New(), nil
	case "sha512":
		return sha512.New(), nil
	}
	return nil, fmt.Errorf("unsupported checksum algorithm %q", algo)
}

// HashFile returns the lowercase hex digest of the file at p.
func HashFile(p, algo string) (string, error) {
	h, err := NewHash(algo)
	if err != nil {
		return "", err
	}
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func isLowerHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return false
		}
	}
	return true
}
