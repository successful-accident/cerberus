package verify

import (
	"bytes"
	"crypto"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/clearsign"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
)

var signedData = []byte("SHA256 (debian-13.7.0-amd64-netinst.iso) = " + h256a + "\n")

// cfgAt is a fast key-generation and signing config whose clock reads now
// shifted by ago.
func cfgAt(ago time.Duration) *packet.Config {
	return &packet.Config{
		Algorithm: packet.PubKeyAlgoEdDSA,
		Time:      func() time.Time { return time.Now().Add(-ago) },
	}
}

func newEntity(t *testing.T, cfg *packet.Config) *openpgp.Entity {
	t.Helper()
	if cfg == nil {
		cfg = cfgAt(0)
	}
	e, err := openpgp.NewEntity("Test", "", "test@example.org", cfg)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func withSigningSubkey(t *testing.T) *openpgp.Entity {
	t.Helper()
	e := newEntity(t, cfgAt(time.Minute))
	if err := e.AddSigningSubkey(cfgAt(time.Minute)); err != nil {
		t.Fatal(err)
	}
	return e
}

func pubBinary(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := e.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func pubArmored(t *testing.T, e *openpgp.Entity) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := armor.Encode(&buf, openpgp.PublicKeyType, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(pubBinary(t, e)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// join concatenates armored blocks one per line, as in a .asc file.
func join(blocks ...[]byte) []byte { return bytes.Join(blocks, []byte("\n")) }

func fpOf(pk *packet.PublicKey) string { return fingerprint(pk) }

func armoredSig(t *testing.T, e *openpgp.Entity, data []byte, cfg *packet.Config) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := openpgp.ArmoredDetachSign(&buf, e, bytes.NewReader(data), cfg); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func binarySig(t *testing.T, e *openpgp.Entity, data []byte, cfg *packet.Config) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := openpgp.DetachSign(&buf, e, bytes.NewReader(data), cfg); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// sha1Sig builds a binary signature with SHA-1, which go-crypto's signing
// helpers won't choose on their own.
func sha1Sig(t *testing.T, e *openpgp.Entity, data []byte) []byte {
	t.Helper()
	sig := &packet.Signature{
		Version:           4,
		SigType:           packet.SigTypeBinary,
		PubKeyAlgo:        e.PrimaryKey.PubKeyAlgo,
		Hash:              crypto.SHA1,
		CreationTime:      time.Now(),
		IssuerKeyId:       &e.PrimaryKey.KeyId,
		IssuerFingerprint: e.PrimaryKey.Fingerprint,
	}
	h, err := sig.PrepareSign(nil)
	if err != nil {
		t.Fatal(err)
	}
	h.Write(data)
	noSalt := &packet.Config{NonDeterministicSignaturesViaNotation: packet.BoolPointer(false)}
	if err := sig.Sign(h, e.PrivateKey, noSalt); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	if err := sig.Serialize(&buf); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestNewKeyring(t *testing.T) {
	a, b := newEntity(t, nil), newEntity(t, nil)
	sub := withSigningSubkey(t)
	fa, fb := fpOf(a.PrimaryKey), fpOf(b.PrimaryKey)
	spaced := strings.ToLower(fa[:4] + " " + fa[4:20] + "  " + fa[20:])
	both := append(pubBinary(t, a), pubBinary(t, b)...)
	twoArmored := join(pubArmored(t, a), pubArmored(t, b))
	for _, c := range []struct {
		name    string
		keys    [][]byte
		fps     []string
		wantErr string
	}{
		{"armored, spaced lowercase fingerprint", [][]byte{pubArmored(t, a)}, []string{spaced}, ""},
		{"binary", [][]byte{pubBinary(t, a)}, []string{fa}, ""},
		{"binary blob with two keys", [][]byte{both}, []string{fa, fb}, ""},
		{"armored blob with two blocks", [][]byte{twoArmored}, []string{fa, fb}, ""},
		{"subkey fingerprint only", [][]byte{pubArmored(t, sub)}, []string{fpOf(sub.Subkeys[1].PublicKey)}, ""},
		{"too short", [][]byte{pubBinary(t, a)}, []string{fa[:39]}, "not 40 hex digits"},
		{"not hex", [][]byte{pubBinary(t, a)}, []string{"G" + fa[1:]}, "not 40 hex digits"},
		{"fingerprint of no key", [][]byte{pubBinary(t, a)}, []string{fa, fb}, "fingerprint " + fb + " matches no key"},
		{"key without allowed fingerprint", [][]byte{both}, []string{fa}, "key " + fb + " has no allowed fingerprint"},
		{"garbage key", [][]byte{[]byte("not a key")}, nil, "reading key blob 1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := NewKeyring(c.keys, c.fps)
			if c.wantErr == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)) {
				t.Fatalf("error = %v, want it to contain %q", err, c.wantErr)
			}
		})
	}
}

func TestVerifyDetached(t *testing.T) {
	a, b := newEntity(t, nil), newEntity(t, nil)
	fa, fb := fpOf(a.PrimaryKey), fpOf(b.PrimaryKey)

	sub := withSigningSubkey(t)
	fsub := fpOf(sub.Subkeys[1].PublicKey) // [0] is the encryption subkey
	fsubPrimary := fpOf(sub.PrimaryKey)
	byPrimary := cfgAt(0)
	byPrimary.SigningKeyId = sub.PrimaryKey.KeyId

	expiredKey := newEntity(t, &packet.Config{
		Algorithm:       packet.PubKeyAlgoEdDSA,
		Time:            func() time.Time { return time.Now().Add(-2 * time.Hour) },
		KeyLifetimeSecs: 3600,
	})
	oldKey := newEntity(t, cfgAt(3*time.Hour))
	shortSig := cfgAt(2 * time.Hour)
	shortSig.SigLifetimeSecs = 60

	revoked := newEntity(t, nil)
	revokedSig := armoredSig(t, revoked, signedData, nil)
	if err := revoked.RevokeKey(packet.KeyCompromised, "", nil); err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte("x"), signedData...)

	for _, c := range []struct {
		name    string
		key     *openpgp.Entity
		allow   []string
		data    []byte
		sig     []byte
		want    string
		wantErr string
	}{
		{"armored sig", a, []string{fa}, signedData, armoredSig(t, a, signedData, nil), fa, ""},
		{"binary sig", a, []string{fa}, signedData, binarySig(t, a, signedData, nil), fa, ""},
		{"two armored blocks, second allowed", b, []string{fb}, signedData,
			join(armoredSig(t, a, signedData, nil), armoredSig(t, b, signedData, nil)), fb, ""},
		{"two binary packets, second allowed", b, []string{fb}, signedData,
			append(binarySig(t, a, signedData, nil), binarySig(t, b, signedData, nil)...), fb, ""},
		{"signing subkey allowed", sub, []string{fsub}, signedData, armoredSig(t, sub, signedData, nil), fsub, ""},
		{"primary allowed, subkey signs", sub, []string{fsubPrimary}, signedData, armoredSig(t, sub, signedData, nil), fsubPrimary, ""},
		{"subkey allowed, primary signs", sub, []string{fsub}, signedData, armoredSig(t, sub, signedData, byPrimary), "", "which is not allowed"},
		{"unknown key", b, []string{fb}, signedData, armoredSig(t, a, signedData, nil), "", "unknown key " + fa},
		{"tampered data", a, []string{fa}, tampered, armoredSig(t, a, signedData, nil), "", "key " + fa},
		{"expired key", expiredKey, []string{fpOf(expiredKey.PrimaryKey)}, signedData,
			armoredSig(t, expiredKey, signedData, cfgAt(90*time.Minute)), "", "expired"},
		{"expired signature", oldKey, []string{fpOf(oldKey.PrimaryKey)}, signedData,
			armoredSig(t, oldKey, signedData, shortSig), "", "expired"},
		{"revoked key", revoked, []string{fpOf(revoked.PrimaryKey)}, signedData, revokedSig, "", "revoked"},
		{"sha1 signature", a, []string{fa}, signedData, sha1Sig(t, a, signedData), "", "weak hash SHA-1"},
		{"empty sig", a, []string{fa}, signedData, nil, "", "no signatures found"},
	} {
		t.Run(c.name, func(t *testing.T) {
			k, err := NewKeyring([][]byte{pubArmored(t, c.key)}, c.allow)
			if err != nil {
				t.Fatal(err)
			}
			got, err := k.VerifyDetached(c.data, c.sig)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("error = %v, want it to contain %q", err, c.wantErr)
				}
				return
			}
			if err != nil || got != c.want {
				t.Fatalf("got %q, %v; want %q, nil", got, err, c.want)
			}
		})
	}
}

// go-crypto's v1 defaults accept SHA-1 message signatures, so the rejection
// in verifyOne is what enforces the policy.
func TestCheckIssuer(t *testing.T) {
	a, b := newEntity(t, nil), newEntity(t, nil)
	kr, err := NewKeyring([][]byte{pubArmored(t, a)}, []string{fpOf(a.PrimaryKey)})
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("an ISO")
	if fp, err := kr.CheckIssuer(armoredSig(t, a, data, nil)); err != nil || fp != fpOf(a.PrimaryKey) {
		t.Errorf("allowed key: %q, %v", fp, err)
	}
	if fp, err := kr.CheckIssuer(join(armoredSig(t, b, data, nil), armoredSig(t, a, data, nil))); err != nil || fp != fpOf(a.PrimaryKey) {
		t.Errorf("second block allowed: %q, %v", fp, err)
	}
	for name, sig := range map[string][]byte{
		"other key": armoredSig(t, b, data, nil),
		"sha1":      sha1Sig(t, a, data),
		"empty":     nil,
		"garbage":   []byte("<html>not a signature</html>"),
	} {
		if _, err := kr.CheckIssuer(sig); err == nil {
			t.Errorf("%s: CheckIssuer accepted it", name)
		}
	}
}

func TestSHA1AcceptedByGoCryptoDefaults(t *testing.T) {
	a := newEntity(t, nil)
	sig := sha1Sig(t, a, signedData)
	if _, err := openpgp.CheckDetachedSignature(openpgp.EntityList{a}, bytes.NewReader(signedData), bytes.NewReader(sig), nil); err != nil {
		t.Fatalf("go-crypto rejected SHA-1 on its own (%v); the explicit check may be redundant", err)
	}
}

func TestVerifyDetachedFile(t *testing.T) {
	a, b := newEntity(t, nil), newEntity(t, nil)
	fb := fpOf(b.PrimaryKey)
	p := filepath.Join(t.TempDir(), "x.iso")
	if err := os.WriteFile(p, signedData, 0o644); err != nil {
		t.Fatal(err)
	}
	k, err := NewKeyring([][]byte{pubBinary(t, b)}, []string{fb})
	if err != nil {
		t.Fatal(err)
	}
	sig := join(armoredSig(t, a, signedData, nil), armoredSig(t, b, signedData, nil))
	if got, err := k.VerifyDetachedFile(p, sig); err != nil || got != fb {
		t.Fatalf("got %q, %v; want %q, nil", got, err, fb)
	}
	if err := os.WriteFile(p, []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := k.VerifyDetachedFile(p, sig); err == nil {
		t.Fatal("tampered file verified")
	}
	if _, err := k.VerifyDetachedFile(filepath.Join(t.TempDir(), "missing"), sig); err == nil {
		t.Fatal("missing file verified")
	}
}

func TestVerifyClearsigned(t *testing.T) {
	a, b := newEntity(t, nil), newEntity(t, nil)
	fa := fpOf(a.PrimaryKey)
	var buf bytes.Buffer
	w, err := clearsign.Encode(&buf, a.PrivateKey, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(signedData)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	evil := h256b + "  evil.iso\n"
	doc := append([]byte(evil), buf.Bytes()...)
	doc = append(doc, []byte("\n"+evil)...)

	k, err := NewKeyring([][]byte{pubArmored(t, a)}, []string{fa})
	if err != nil {
		t.Fatal(err)
	}
	plain, fp, err := k.VerifyClearsigned(doc)
	if err != nil || fp != fa {
		t.Fatalf("got %q, %v; want %q, nil", fp, err, fa)
	}
	if strings.Contains(string(plain), "evil") || !strings.Contains(string(plain), strings.TrimSpace(string(signedData))) {
		t.Fatalf("plaintext = %q", plain)
	}

	kb, err := NewKeyring([][]byte{pubArmored(t, b)}, []string{fpOf(b.PrimaryKey)})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := kb.VerifyClearsigned(doc); err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("error = %v, want unknown key", err)
	}
	tampered := bytes.Replace(doc, []byte("debian"), []byte("dabian"), 1)
	if _, _, err := k.VerifyClearsigned(tampered); err == nil {
		t.Fatal("tampered document verified")
	}
	if _, _, err := k.VerifyClearsigned(signedData); err == nil {
		t.Fatal("unsigned document verified")
	}
}
