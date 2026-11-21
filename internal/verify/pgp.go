package verify

import "github.com/ProtonMail/go-crypto/openpgp"

// Keyring verifies OpenPGP signatures made by an allowed set of keys.
type Keyring struct {
	keys    openpgp.EntityList
	allowed map[string]bool // uppercase hex fingerprints
}

// NewKeyring parses public keys, armored or binary, with possibly several
// keys per blob, and the fingerprints allowed to sign. Fingerprints are 40
// hex digits; spaces are ignored and case doesn't matter. Each fingerprint
// must belong to a primary key or subkey in keys, and every key must have at
// least one allowed fingerprint. Anything else is an error.
func NewKeyring(keys [][]byte, fingerprints []string) (*Keyring, error) {
	panic("verify.NewKeyring: not implemented (phase 1)")
}

// VerifyDetached checks a detached signature over data. sig may be binary or
// armored, and an armored sig may hold several signature blocks. It passes
// if any block is a valid signature by an allowed key (the primary key or
// signing subkey whose fingerprint is allowed), and returns that
// fingerprint. Expired, revoked, or weak-hash signatures fail.
func (k *Keyring) VerifyDetached(data, sig []byte) (string, error) {
	panic("verify.Keyring.VerifyDetached: not implemented (phase 1)")
}

// VerifyDetachedFile is VerifyDetached over the file at path, which it
// re-reads for each signature block, so a multi-gigabyte ISO never sits in
// memory.
func (k *Keyring) VerifyDetachedFile(path string, sig []byte) (string, error) {
	panic("verify.Keyring.VerifyDetachedFile: not implemented (phase 1)")
}

// VerifyClearsigned verifies a clearsigned document and returns only its
// signed plaintext, plus the allowed fingerprint that signed it. Text before
// the BEGIN line or after the signature is never returned.
func (k *Keyring) VerifyClearsigned(doc []byte) (plaintext []byte, fingerprint string, err error) {
	panic("verify.Keyring.VerifyClearsigned: not implemented (phase 1)")
}
