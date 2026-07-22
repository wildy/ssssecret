package roundtrip

import (
	"bytes"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/hashicorp/vault/shamir"

	"github.com/wildy/ssssecret/internal/cryptox"
	"github.com/wildy/ssssecret/internal/inputscan"
	"github.com/wildy/ssssecret/internal/pdfgen"
	"github.com/wildy/ssssecret/internal/qrpayload"
	"github.com/wildy/ssssecret/internal/recover"
)

// Mirrors the full app flow: compress, encrypt, split, render PDF,
// then scan the PDF back and recover the secret from it.
func TestRoundTrip_PDFScanRecover(t *testing.T) {
	// Random bytes are incompressible, forcing multiple ciphertext chunks.
	secret, err := cryptox.RandomBytes(3500)
	if err != nil {
		t.Fatal(err)
	}
	docID, err := qrpayload.NewDocID()
	if err != nil {
		t.Fatal(err)
	}
	n, threshold, chunkSize := 5, 3, 1501

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
	compressed, err := cryptox.CompressGzip(secret)
	if err != nil {
		t.Fatal(err)
	}
	env, err := cryptox.EncryptAES256GCM(compressed, key, []byte(docID))
	if err != nil {
		t.Fatal(err)
	}
	shares, err := shamir.Split(x, n, threshold)
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := qrpayload.SplitBytes(env.Ciphertext, chunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(chunks) < 2 {
		t.Fatalf("want multiple ciphertext chunks, got %d", len(chunks))
	}

	var cipherItems []pdfgen.Item
	for i, c := range chunks {
		p := qrpayload.CipherChunkV1{
			Common:     qrpayload.Common{V: qrpayload.Version, Type: qrpayload.TypeCipherChunk, Doc: docID},
			KDF:        "HKDF-SHA256",
			AEAD:       "AES-256-GCM",
			Comp:       "gzip",
			N:          n,
			T:          threshold,
			SaltB64:    qrpayload.B64(salt),
			NonceB64:   qrpayload.B64(env.Nonce),
			ChunkIndex: i + 1,
			ChunkTotal: len(chunks),
			DataB64:    qrpayload.B64(c),
		}
		s, err := qrpayload.MarshalJSON(p)
		if err != nil {
			t.Fatal(err)
		}
		cipherItems = append(cipherItems, pdfgen.Item{
			Title:   fmt.Sprintf("DOC %s CIPHERTEXT %d/%d", docID, i+1, len(chunks)),
			Payload: s,
		})
	}
	var shareItems []pdfgen.Item
	for i, sh := range shares {
		p := qrpayload.ShareV1{
			Common:   qrpayload.Common{V: qrpayload.Version, Type: qrpayload.TypeShare, Doc: docID},
			N:        n,
			T:        threshold,
			ShareB64: qrpayload.B64(sh),
		}
		s, err := qrpayload.MarshalJSON(p)
		if err != nil {
			t.Fatal(err)
		}
		shareItems = append(shareItems, pdfgen.Item{
			Title:   fmt.Sprintf("DOC %s // SHARE %d/%d (need %d)", docID, i+1, n, threshold),
			Payload: s,
		})
	}

	pdfPath := filepath.Join(t.TempDir(), "roundtrip.pdf")
	if err := pdfgen.RenderCiphertextThenShares(cipherItems, shareItems, pdfPath, pdfgen.DefaultOptions()); err != nil {
		t.Fatalf("render PDF: %v", err)
	}

	txts, err := inputscan.ScanFile(pdfPath)
	if err != nil {
		t.Fatalf("ScanFile: %v", err)
	}
	if want := len(cipherItems) + len(shareItems); len(txts) != want {
		t.Fatalf("ScanFile returned %d payloads, want %d", len(txts), want)
	}

	groups, err := recover.ParseAndGroup(txts)
	if err != nil {
		t.Fatalf("ParseAndGroup: %v", err)
	}
	g, ok := groups[docID]
	if !ok {
		t.Fatalf("doc %s not found in groups", docID)
	}
	res, err := recover.RecoverSecret(g)
	if err != nil {
		t.Fatalf("RecoverSecret: %v", err)
	}
	if !bytes.Equal(res.Secret, secret) {
		t.Fatalf("recovered secret mismatch: got %d bytes, want %d bytes", len(res.Secret), len(secret))
	}
}
