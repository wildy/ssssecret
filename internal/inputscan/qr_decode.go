package inputscan

import (
	"image"
	"image/draw"

	"github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/multi/qrcode"
)

// DecodeQRPayloadsFromImage returns all QR texts found in the image.
// It tries multiple rotations and de-dupes results.
func DecodeQRPayloadsFromImage(img image.Image) ([]string, error) {
	hints := map[gozxing.DecodeHintType]interface{}{
		gozxing.DecodeHintType_TRY_HARDER: true,
	}

	mr := qrcode.NewQRCodeMultiReader()
	seen := map[string]struct{}{}
	var out []string

	var lastErr error
	for _, im := range []image.Image{toRGBA(img), toRGBA(rotate90(img)), toRGBA(rotate180(img)), toRGBA(rotate270(img))} {
		bmp, err := gozxing.NewBinaryBitmapFromImage(im)
		if err != nil {
			lastErr = err
			continue
		}
		results, err := mr.DecodeMultiple(bmp, hints)
		if err != nil {
			lastErr = err
			continue
		}
		for _, r := range results {
			txt := r.GetText()
			if _, ok := seen[txt]; ok {
				continue
			}
			seen[txt] = struct{}{}
			out = append(out, txt)
		}
	}
	if len(out) == 0 && lastErr != nil {
		return nil, lastErr
	}
	return out, nil
}

func rotate90(src image.Image) image.Image {
	b := src.Bounds()
	dst := image.NewRGBA(image.Rect(0, 0, b.Dy(), b.Dx()))
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			// Normalize to the zero-origin destination so sources with
			// non-zero-origin bounds (e.g. SubImage crops) rotate correctly.
			dst.Set(b.Max.Y-1-y, x-b.Min.X, src.At(x, y))
		}
	}
	return dst
}

func rotate180(src image.Image) image.Image {
	return rotate90(rotate90(src))
}

func rotate270(src image.Image) image.Image {
	return rotate90(rotate180(src))
}

// Ensure we preserve alpha for some decoders, and normalize to RGBA.
func toRGBA(src image.Image) *image.RGBA {
	b := src.Bounds()
	dst := image.NewRGBA(image.Rect(0, 0, b.Dx(), b.Dy()))
	draw.Draw(dst, dst.Bounds(), src, b.Min, draw.Src)
	return dst
}
