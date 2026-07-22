package roundtrip

import (
	"bytes"
	"testing"

	qrgen "github.com/skip2/go-qrcode"

	"github.com/wildy/ssssecret/internal/cryptox"
	"github.com/wildy/ssssecret/internal/inputscan"
	"github.com/wildy/ssssecret/internal/pdfgen"
	"github.com/wildy/ssssecret/internal/qrpayload"
)

// A payload built from a MaxChunkSize chunk with worst-case framing (widest
// n/t/index fields) must fit in a QR at the app's ECC level and be decodable
// at the app's default pixel size.
func TestMaxChunkSizePayload_FitsAndDecodes(t *testing.T) {
	chunk, err := cryptox.RandomBytes(qrpayload.MaxChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	salt, err := cryptox.RandomBytes(cryptox.SaltSizeBytes)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := cryptox.RandomBytes(cryptox.NonceSize)
	if err != nil {
		t.Fatal(err)
	}
	docID, err := qrpayload.NewDocID()
	if err != nil {
		t.Fatal(err)
	}

	payload, err := qrpayload.MarshalJSON(qrpayload.CipherChunkV1{
		Common:     qrpayload.Common{V: qrpayload.Version, Type: qrpayload.TypeCipherChunk, Doc: docID},
		KDF:        "HKDF-SHA256",
		AEAD:       "AES-256-GCM",
		Comp:       "gzip",
		N:          255,
		T:          255,
		SaltB64:    qrpayload.B64(salt),
		NonceB64:   qrpayload.B64(nonce),
		ChunkIndex: 9999,
		ChunkTotal: 9999,
		DataB64:    qrpayload.B64(chunk),
	})
	if err != nil {
		t.Fatal(err)
	}

	opts := pdfgen.DefaultOptions()
	qr, err := qrgen.New(payload, opts.ErrorLevel)
	if err != nil {
		t.Fatalf("payload of %d chars does not fit in a QR: %v", len(payload), err)
	}
	img := qr.Image(opts.QRPixelSize)
	txts, err := inputscan.DecodeQRPayloadsFromImage(img)
	if err != nil {
		t.Fatalf("decode at %dpx: %v", opts.QRPixelSize, err)
	}
	if len(txts) != 1 || !bytes.Equal([]byte(txts[0]), []byte(payload)) {
		t.Fatalf("decoded %d texts, roundtrip mismatch", len(txts))
	}
}
