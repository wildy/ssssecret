package inputscan

import (
	"image"
	"image/draw"
	"os"
	"path/filepath"
	"testing"

	"github.com/hhrutter/tiff"
	qrgen "github.com/skip2/go-qrcode"
)

// pdfcpu writes CMYK image XObjects as CMYK TIFFs; golang.org/x/image/tiff
// cannot decode those, the hhrutter fork we import can.
func TestDecodeImageFile_CMYKTiff(t *testing.T) {
	want := `{"v":1,"type":"share","doc":"TIFFTESTDOC12345","n":5,"t":3,"share_b64":"AA=="}`
	qr, err := qrgen.New(want, qrgen.Medium)
	if err != nil {
		t.Fatal(err)
	}
	src := qr.Image(512)
	cmyk := image.NewCMYK(src.Bounds())
	draw.Draw(cmyk, src.Bounds(), src, src.Bounds().Min, draw.Src)

	p := filepath.Join(t.TempDir(), "qr-cmyk.tif")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := tiff.Encode(f, cmyk, nil); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	img, err := DecodeImageFile(p)
	if err != nil {
		t.Fatalf("DecodeImageFile: %v", err)
	}
	txts, err := DecodeQRPayloadsFromImage(img)
	if err != nil {
		t.Fatal(err)
	}
	if len(txts) != 1 || txts[0] != want {
		t.Fatalf("decoded %v, want the original payload", txts)
	}
}
