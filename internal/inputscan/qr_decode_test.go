package inputscan

import (
	"testing"

	qrgen "github.com/skip2/go-qrcode"
)

func TestDecodeQRPayloadsFromImage_Single(t *testing.T) {
	want := `{"v":1,"type":"cipher","doc":"TEST","kdf":"HKDF-SHA256","aead":"AES-256-GCM","n":5,"t":3,"salt_b64":"AA==","nonce_b64":"AA==","chunk_index":1,"chunk_total":1,"data_b64":"AA=="}` // doesn't need to be valid to decode QR text
	qr, err := qrgen.New(want, qrgen.Medium)
	if err != nil {
		t.Fatal(err)
	}
	img := qr.Image(512)

	txts, err := DecodeQRPayloadsFromImage(img)
	if err != nil {
		t.Fatal(err)
	}
	if len(txts) != 1 {
		t.Fatalf("len(txts)=%d, want 1", len(txts))
	}
	if txts[0] != want {
		t.Fatalf("decoded mismatch\n got: %q\nwant: %q", txts[0], want)
	}
}


