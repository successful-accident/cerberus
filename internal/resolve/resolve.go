// Package resolve runs a catalog entry's steps against live feeds and
// returns the newest release: its version, download URL, file name,
// checksum, and signature details.
package resolve

import (
	"context"

	_ "github.com/itchyny/gojq" // used by jq steps
	_ "go.yaml.in/yaml/v3"      // used to read YAML feeds for jq steps

	"github.com/successful-accident/cerberus/internal/catalog"
	"github.com/successful-accident/cerberus/internal/download"
	"github.com/successful-accident/cerberus/internal/verify"
)

// Fetcher fetches documents over HTTPS. *download.Client satisfies it.
type Fetcher interface {
	Get(ctx context.Context, url string) (*download.Doc, error)
	Head(ctx context.Context, url string) (*download.Doc, error)
}

// Verifier checks OpenPGP signatures against an entry's pinned keys.
// *verify.Keyring satisfies it.
type Verifier interface {
	VerifyDetached(data, sig []byte) (fingerprint string, err error)
	VerifyClearsigned(doc []byte) (plaintext []byte, fingerprint string, err error)
}

// Options tune one resolution.
type Options struct {
	// Arch is amd64 or arm64, and must be a key of the entry's Arch map.
	Arch string
	// Pin is an optional version prefix; see MatchesPin.
	Pin string
	// Verifier is required when the entry has a clearsigned step or a
	// detached-checksums signature.
	Verifier Verifier
	// Fallback is how many more candidates a step tries after its best one
	// fails in a later step. Zero means 3.
	Fallback int
}

// Release is a resolved ISO that hasn't been downloaded yet.
type Release struct {
	EntryID  string
	Version  string
	URL      string
	Filename string
	Checksum verify.Checksum
	// SignedBy is the fingerprint that signed the document the checksum came
	// from, or "" when that document is unsigned.
	SignedBy string
	// ISOSignatureURL is set for detached-iso entries. The caller checks the
	// downloaded file against it.
	ISOSignatureURL string
	// Vars holds every variable at the end of resolution, for debugging.
	Vars map[string]string
}

// Resolve runs e's steps and returns the newest release.
//
// It starts with the variable arch set to e.Arch[opt.Arch], and fails if
// that key is missing. Then, for each step in order:
//  1. Render Fetch with catalog.Render, without quoting. Fetch it with Get
//     when From is body or empty; otherwise use Head.
//  2. Take the step's text from From. With Clearsigned, verify the body
//     with opt.Verifier and use only the returned plaintext.
//  3. Extract candidates. For Match, replace placeholders with
//     regexp.QuoteMeta'd values, compile, and make one candidate per match.
//     For JQ, parse the body as JSON (YAML when that fails), pass every
//     variable as $name, and make one candidate per output object; numbers
//     are formatted without exponents.
//  4. Drop candidates whose text matches Exclude, and, when opt.Pin is set,
//     candidates whose version fails MatchesPin. Drop exact duplicates.
//  5. Sort candidates newest first with CompareVersions when they carry a
//     version, else keep document order. No candidates is an error that
//     names the step.
//  6. Try the candidates in order, each merged over the current variables,
//     running the remaining steps and the finish below. If that fails with
//     an error other than the context's, try the next one, up to 1 +
//     opt.Fallback candidates. Return the last error if all fail.
//
// To finish, Resolve renders e.URL, which must be an https:// URL. The file
// name is e.Filename rendered, or the URL path's last segment, unescaped. It
// must pass catalog.ValidFilename and contain the version variable, which
// must exist. The checksum is the sha512 variable, else sha256, else the
// e.Checksum sidecar, with url and filename added as variables. It must be
// valid hex of the right length, and is stored lowercase. For a
// detached-checksums signature, Resolve fetches the rendered Signature.URL
// and verifies it over the raw bytes of the document that produced the
// checksum. When that document was clearsigned, its signer counts too. For
// detached-iso, it only renders ISOSignatureURL.
func Resolve(ctx context.Context, f Fetcher, e *catalog.Entry, opt Options) (*Release, error) {
	panic("resolve.Resolve: not implemented (phase 1)")
}

// CompareVersions orders version strings naturally and returns -1, 0 or +1.
// Runs of digits compare as numbers, ignoring leading zeros. Runs of letters
// compare as text. Any other character only separates runs. When one
// version's runs are a prefix of the other's, the longer version is newer.
// So 9.10 > 9.9, 2026.3a > 2026.3, and 20261115T170104Z > 20261108T000000Z.
func CompareVersions(a, b string) int {
	panic("resolve.CompareVersions: not implemented (phase 1)")
}

// MatchesPin reports whether version equals pin, or starts with pin followed
// by a character that is neither a letter nor a digit. An empty pin matches
// every version. So pin 24.04 matches 24.04 and 24.04.3, but not 24.040, and
// pin 9 matches 9.6 and 9-1, but not 90.
func MatchesPin(version, pin string) bool {
	panic("resolve.MatchesPin: not implemented (phase 1)")
}
