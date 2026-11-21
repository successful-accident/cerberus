package verify

import (
	"bufio"
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

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
	k := &Keyring{allowed: map[string]bool{}}
	for i, blob := range keys {
		el, err := readKeys(blob)
		if err != nil {
			return nil, fmt.Errorf("reading key blob %d: %w", i+1, err)
		}
		k.keys = append(k.keys, el...)
	}
	known := map[string]bool{}
	for _, e := range k.keys {
		for _, fp := range entityFingerprints(e) {
			known[fp] = true
		}
	}
	for _, raw := range fingerprints {
		fp := strings.ToUpper(strings.ReplaceAll(raw, " ", ""))
		if !isUpperHex40(fp) {
			return nil, fmt.Errorf("fingerprint %q is not 40 hex digits", raw)
		}
		if !known[fp] {
			return nil, fmt.Errorf("fingerprint %s matches no key", fp)
		}
		k.allowed[fp] = true
	}
	for _, e := range k.keys {
		ok := false
		for _, fp := range entityFingerprints(e) {
			ok = ok || k.allowed[fp]
		}
		if !ok {
			return nil, fmt.Errorf("key %s has no allowed fingerprint", fingerprint(e.PrimaryKey))
		}
	}
	return k, nil
}

// VerifyDetached checks a detached signature over data. sig may be binary or
// armored, and an armored sig may hold several signature blocks. It passes
// if any block is a valid signature by an allowed key (the primary key or
// signing subkey whose fingerprint is allowed), and returns that
// fingerprint. Expired, revoked, or weak-hash signatures fail, and so does
// a sig with more than MaxSignatures signature packets.
func (k *Keyring) VerifyDetached(data, sig []byte) (string, error) {
	return k.verify(sig, func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(data)), nil
	})
}

// VerifyDetachedFile is VerifyDetached over the file at path, which it
// re-reads for each signature block, so a multi-gigabyte ISO never sits in
// memory. MaxSignatures bounds how often a hostile signature file can make
// it read the ISO.
func (k *Keyring) VerifyDetachedFile(path string, sig []byte) (string, error) {
	return k.verify(sig, func() (io.ReadCloser, error) { return os.Open(path) })
}

// VerifyClearsigned verifies a clearsigned document and returns only its
// signed plaintext, plus the allowed fingerprint that signed it. Text before
// the BEGIN line or after the signature is never returned. More than
// MaxSignatures signature packets fail.
func (k *Keyring) VerifyClearsigned(doc []byte) (plaintext []byte, fingerprint string, err error) {
	block, _ := clearsign.Decode(doc)
	if block == nil {
		return nil, "", errors.New("no clearsigned message found")
	}
	body, err := io.ReadAll(block.ArmoredSignature.Body)
	if err != nil {
		return nil, "", fmt.Errorf("reading clearsigned signature: %w", err)
	}
	fp, err := k.verifyPackets(splitPackets([][]byte{body}), func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(block.Bytes)), nil
	})
	if err != nil {
		return nil, "", err
	}
	return block.Plaintext, fp, nil
}

// sigPacket is one signature packet from a detached signature, or the error
// that kept it from parsing.
type sigPacket struct {
	raw []byte
	sig *packet.Signature
	err error
}

// CheckIssuer reports the allowed fingerprint that a detached signature
// names as its signer, without the signed data. It doesn't verify the
// signature cryptographically; that happens at download time with
// VerifyDetachedFile. It catches what a catalog check can see in advance: a
// missing or unreadable signature file, a weak hash, more than
// MaxSignatures signatures, and a distro that has moved to a key the entry
// doesn't pin.
func (k *Keyring) CheckIssuer(sig []byte) (string, error) {
	sigs, err := sigPackets(sig)
	if err != nil {
		return "", err
	}
	if err := countSignatures(sigs); err != nil {
		return "", err
	}
	var fails []string
	for i, s := range sigs {
		fp, err := k.issuerOne(s)
		if err == nil {
			return fp, nil
		}
		fails = append(fails, fmt.Sprintf("signature %d: %v", i+1, err))
	}
	return "", fmt.Errorf("no signature names an allowed key: %s", strings.Join(fails, "; "))
}

func (k *Keyring) issuerOne(s sigPacket) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	if s.sig.IssuerKeyId == nil {
		return "", errors.New("signature names no issuer")
	}
	if !strongHashes[s.sig.Hash] {
		return "", fmt.Errorf("key %s used weak hash %v", issuerName(s.sig), s.sig.Hash)
	}
	keys := k.keys.KeysById(*s.sig.IssuerKeyId)
	if len(keys) == 0 {
		return "", fmt.Errorf("unknown key %s", issuerName(s.sig))
	}
	return k.allowedSigner(keys[0].Entity, s.sig)
}

// sigPackets splits a binary or armored detached signature into its
// signature packets.
func sigPackets(sig []byte) ([]sigPacket, error) {
	bodies := [][]byte{sig}
	if bytes.HasPrefix(bytes.TrimSpace(sig), []byte("-----BEGIN PGP SIGNATURE-----")) {
		var err error
		if bodies, err = armorBodies(sig, openpgp.SignatureType); err != nil {
			return nil, err
		}
	}
	return splitPackets(bodies), nil
}

func (k *Keyring) verify(sig []byte, open func() (io.ReadCloser, error)) (string, error) {
	sigs, err := sigPackets(sig)
	if err != nil {
		return "", err
	}
	return k.verifyPackets(sigs, open)
}

// MaxSignatures is the most signature packets one signature accepts. Each
// packet by a pinned key costs a full read of the signed data, so padding a
// file with stale signatures would otherwise make a verify read a
// multi-gigabyte ISO thousands of times. The catalog's most is two.
const MaxSignatures = 8

func countSignatures(sigs []sigPacket) error {
	switch {
	case len(sigs) == 0:
		return errors.New("no signatures found")
	case len(sigs) > MaxSignatures:
		return fmt.Errorf("%d signatures in one file; more than %d is refused", len(sigs), MaxSignatures)
	}
	return nil
}

// verifyPackets passes when any packet is a valid signature by an allowed
// key, and otherwise reports every packet's failure.
func (k *Keyring) verifyPackets(sigs []sigPacket, open func() (io.ReadCloser, error)) (string, error) {
	if err := countSignatures(sigs); err != nil {
		return "", err
	}
	var fails []string
	for i, s := range sigs {
		fp, err := k.verifyOne(s, open)
		if err == nil {
			return fp, nil
		}
		fails = append(fails, fmt.Sprintf("signature %d: %v", i+1, err))
	}
	return "", fmt.Errorf("no valid signature by an allowed key: %s", strings.Join(fails, "; "))
}

func (k *Keyring) verifyOne(s sigPacket, open func() (io.ReadCloser, error)) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	if s.sig.IssuerKeyId == nil {
		return "", errors.New("signature names no issuer")
	}
	issuer := issuerName(s.sig)
	// go-crypto's v1 API accepts SHA-1 message signatures, so the hash
	// policy is enforced here, before the data is read.
	if !strongHashes[s.sig.Hash] {
		return "", fmt.Errorf("key %s used weak hash %v", issuer, s.sig.Hash)
	}
	if len(k.keys.KeysById(*s.sig.IssuerKeyId)) == 0 {
		return "", fmt.Errorf("unknown key %s", issuer)
	}
	r, err := open()
	if err != nil {
		return "", err
	}
	defer r.Close()
	// VerifyDetachedSignature also fails expired signatures and expired
	// or revoked keys.
	sig, signer, err := openpgp.VerifyDetachedSignature(k.keys, r, bytes.NewReader(s.raw), nil)
	if err != nil {
		return "", fmt.Errorf("key %s: %w", issuer, err)
	}
	return k.allowedSigner(signer, sig)
}

// allowedSigner returns the allowed fingerprint of the key that made sig, or
// of its primary key.
func (k *Keyring) allowedSigner(e *openpgp.Entity, sig *packet.Signature) (string, error) {
	keys := []*packet.PublicKey{e.PrimaryKey}
	for _, sk := range e.Subkeys {
		keys = append(keys, sk.PublicKey)
	}
	for _, pk := range keys {
		if pk.KeyId != *sig.IssuerKeyId || sig.IssuerFingerprint != nil && !bytes.Equal(pk.Fingerprint, sig.IssuerFingerprint) {
			continue
		}
		for _, fp := range []string{fingerprint(pk), fingerprint(e.PrimaryKey)} {
			if k.allowed[fp] {
				return fp, nil
			}
		}
		return "", fmt.Errorf("signed by key %s, which is not allowed", fingerprint(pk))
	}
	return "", fmt.Errorf("signing key %s not found in its entity", issuerName(sig))
}

// strongHashes are the signature hashes accepted. SHA-1 and weaker fail.
var strongHashes = map[crypto.Hash]bool{
	crypto.SHA224:   true,
	crypto.SHA256:   true,
	crypto.SHA384:   true,
	crypto.SHA512:   true,
	crypto.SHA3_256: true,
	crypto.SHA3_512: true,
}

// splitPackets reads each body as a packet stream and returns every
// signature packet in it, re-serialized on its own so each can be checked
// separately.
func splitPackets(bodies [][]byte) []sigPacket {
	var out []sigPacket
	for _, body := range bodies {
		pr := packet.NewReader(bytes.NewReader(body))
		for {
			p, err := pr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				out = append(out, sigPacket{err: fmt.Errorf("parsing signature: %w", err)})
				break
			}
			sig, ok := p.(*packet.Signature)
			if !ok {
				out = append(out, sigPacket{err: fmt.Errorf("unexpected %T in signature", p)})
				continue
			}
			var buf bytes.Buffer
			if err := sig.Serialize(&buf); err != nil {
				out = append(out, sigPacket{err: fmt.Errorf("re-encoding signature: %w", err)})
				continue
			}
			out = append(out, sigPacket{raw: buf.Bytes(), sig: sig})
		}
	}
	return out
}

// armorBodies decodes every armored block in data, which must all be of
// type typ. armor.Decode reads one block, so it's called until EOF on a
// shared buffered reader.
func armorBodies(data []byte, typ string) ([][]byte, error) {
	br := bufio.NewReader(bytes.NewReader(data))
	var out [][]byte
	for {
		block, err := armor.Decode(br)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decoding armor block %d: %w", len(out)+1, err)
		}
		if block.Type != typ {
			return nil, fmt.Errorf("armor block %d is %q, want %q", len(out)+1, block.Type, typ)
		}
		body, err := io.ReadAll(block.Body)
		if err != nil {
			return nil, fmt.Errorf("decoding armor block %d: %w", len(out)+1, err)
		}
		out = append(out, body)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no %s found", typ)
	}
	return out, nil
}

func readKeys(blob []byte) (openpgp.EntityList, error) {
	if !bytes.HasPrefix(bytes.TrimSpace(blob), []byte("-----BEGIN PGP PUBLIC KEY BLOCK-----")) {
		return openpgp.ReadKeyRing(bytes.NewReader(blob))
	}
	bodies, err := armorBodies(blob, openpgp.PublicKeyType)
	if err != nil {
		return nil, err
	}
	var el openpgp.EntityList
	for _, body := range bodies {
		l, err := openpgp.ReadKeyRing(bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		el = append(el, l...)
	}
	return el, nil
}

func entityFingerprints(e *openpgp.Entity) []string {
	fps := []string{fingerprint(e.PrimaryKey)}
	for _, sk := range e.Subkeys {
		fps = append(fps, fingerprint(sk.PublicKey))
	}
	return fps
}

func fingerprint(pk *packet.PublicKey) string {
	return strings.ToUpper(hex.EncodeToString(pk.Fingerprint))
}

func issuerName(sig *packet.Signature) string {
	if sig.IssuerFingerprint != nil {
		return strings.ToUpper(hex.EncodeToString(sig.IssuerFingerprint))
	}
	return fmt.Sprintf("%016X", *sig.IssuerKeyId)
}

func isUpperHex40(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, r := range s {
		if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}
