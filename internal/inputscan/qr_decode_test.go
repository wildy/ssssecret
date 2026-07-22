package inputscan

import (
	"image"
	"image/color"
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

// rotate90 must treat a source with non-zero-origin bounds (e.g. a SubImage
// crop) the same as its zero-origin equivalent.
func TestRotate90_NonZeroOriginBounds(t *testing.T) {
	const w, h = 3, 2
	px := func(x, y int) color.RGBA {
		return color.RGBA{R: uint8(10 + x), G: uint8(100 + y), B: uint8(x * y), A: 255}
	}
	base := image.NewRGBA(image.Rect(0, 0, w, h))
	shifted := image.NewRGBA(image.Rect(4, 9, 4+w, 9+h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			base.Set(x, y, px(x, y))
			shifted.Set(4+x, 9+y, px(x, y))
		}
	}

	got := rotate90(shifted)
	want := rotate90(base)
	if got.Bounds() != want.Bounds() {
		t.Fatalf("bounds mismatch: got %v, want %v", got.Bounds(), want.Bounds())
	}
	for y := 0; y < w; y++ { // rotated: width and height swap
		for x := 0; x < h; x++ {
			if got.At(x, y) != want.At(x, y) {
				t.Fatalf("pixel (%d,%d): got %v, want %v", x, y, got.At(x, y), want.At(x, y))
			}
		}
	}
}
