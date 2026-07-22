package recover

import (
	"bytes"
	"testing"

	"github.com/hashicorp/vault/shamir"

	"github.com/wildy/ssssecret/internal/cryptox"
	"github.com/wildy/ssssecret/internal/qrpayload"
)

// A re-scanned share page yields the same payload twice; recovery must still
// succeed as long as enough distinct shares are present.
func TestRecoverSecret_DuplicateSharesScanned(t *testing.T) {
	secret := []byte("duplicate-share regression secret")
	docID := "DUPSHAREDOC12345"
	n, threshold := 5, 3

	x, err := cryptox.GenerateX()
	if err != nil {
		t.Fatal(err)
	}
	salt, err := cryptox.RandomBytes(cryptox.SaltSizeBytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cryptox.DeriveAES256Key(x, salt)
	if err != nil {
		t.Fatal(err)
	}
	env, err := cryptox.EncryptAES256GCM(secret, key, []byte(docID))
	if err != nil {
		t.Fatal(err)
	}
	shares, err := shamir.Split(x, n, threshold)
	if err != nil {
		t.Fatal(err)
	}

	cipherPayload, err := qrpayload.MarshalJSON(qrpayload.CipherChunkV1{
		Common:     qrpayload.Common{V: qrpayload.Version, Type: qrpayload.TypeCipherChunk, Doc: docID},
		KDF:        "HKDF-SHA256",
		AEAD:       "AES-256-GCM",
		N:          n,
		T:          threshold,
		SaltB64:    qrpayload.B64(salt),
		NonceB64:   qrpayload.B64(env.Nonce),
		ChunkIndex: 1,
		ChunkTotal: 1,
		DataB64:    qrpayload.B64(env.Ciphertext),
	})
	if err != nil {
		t.Fatal(err)
	}

	sharePayload := func(i int) string {
		s, err := qrpayload.MarshalJSON(qrpayload.ShareV1{
			Common:   qrpayload.Common{V: qrpayload.Version, Type: qrpayload.TypeShare, Doc: docID},
			N:        n,
			T:        threshold,
			ShareB64: qrpayload.B64(shares[i]),
		})
		if err != nil {
			t.Fatal(err)
		}
		return s
	}

	// Share 0 scanned twice (e.g. a re-taken photo), then two distinct shares:
	// exactly threshold distinct shares in total.
	payloads := []string{cipherPayload, sharePayload(0), sharePayload(0), sharePayload(1), sharePayload(2)}

	groups, err := ParseAndGroup(payloads)
	if err != nil {
		t.Fatal(err)
	}
	g, ok := groups[docID]
	if !ok {
		t.Fatalf("doc %s not grouped", docID)
	}
	if len(g.Shares) != threshold {
		t.Fatalf("len(Shares)=%d, want %d distinct", len(g.Shares), threshold)
	}
	res, err := RecoverSecret(g)
	if err != nil {
		t.Fatalf("RecoverSecret: %v", err)
	}
	if !bytes.Equal(res.Secret, secret) {
		t.Fatalf("recovered secret mismatch")
	}
}

// Adding the same file twice duplicates every payload; recovery must be unaffected.
func TestRecoverSecret_WholeDocScannedTwice(t *testing.T) {
	secret := []byte("whole-doc duplicate regression secret")
	docID := "DUPDOCDOC1234567"
	n, threshold := 4, 2

	x, err := cryptox.GenerateX()
	if err != nil {
		t.Fatal(err)
	}
	salt, err := cryptox.RandomBytes(cryptox.SaltSizeBytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cryptox.DeriveAES256Key(x, salt)
	if err != nil {
		t.Fatal(err)
	}
	env, err := cryptox.EncryptAES256GCM(secret, key, []byte(docID))
	if err != nil {
		t.Fatal(err)
	}
	shares, err := shamir.Split(x, n, threshold)
	if err != nil {
		t.Fatal(err)
	}

	var payloads []string
	p, err := qrpayload.MarshalJSON(qrpayload.CipherChunkV1{
		Common:     qrpayload.Common{V: qrpayload.Version, Type: qrpayload.TypeCipherChunk, Doc: docID},
		KDF:        "HKDF-SHA256",
		AEAD:       "AES-256-GCM",
		N:          n,
		T:          threshold,
		SaltB64:    qrpayload.B64(salt),
		NonceB64:   qrpayload.B64(env.Nonce),
		ChunkIndex: 1,
		ChunkTotal: 1,
		DataB64:    qrpayload.B64(env.Ciphertext),
	})
	if err != nil {
		t.Fatal(err)
	}
	payloads = append(payloads, p)
	for i := range shares {
		s, err := qrpayload.MarshalJSON(qrpayload.ShareV1{
			Common:   qrpayload.Common{V: qrpayload.Version, Type: qrpayload.TypeShare, Doc: docID},
			N:        n,
			T:        threshold,
			ShareB64: qrpayload.B64(shares[i]),
		})
		if err != nil {
			t.Fatal(err)
		}
		payloads = append(payloads, s)
	}
	payloads = append(payloads, payloads...) // same file scanned twice

	groups, err := ParseAndGroup(payloads)
	if err != nil {
		t.Fatal(err)
	}
	g, ok := groups[docID]
	if !ok {
		t.Fatalf("doc %s not grouped", docID)
	}
	if len(g.Shares) != n {
		t.Fatalf("len(Shares)=%d, want %d distinct", len(g.Shares), n)
	}
	res, err := RecoverSecret(g)
	if err != nil {
		t.Fatalf("RecoverSecret: %v", err)
	}
	if !bytes.Equal(res.Secret, secret) {
		t.Fatalf("recovered secret mismatch")
	}
}
