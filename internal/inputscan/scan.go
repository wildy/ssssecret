package inputscan

import (
	"fmt"
	"path/filepath"
)

// ScanFile extracts all QR payload texts from a supported file (PDF or image).
func ScanFile(path string) ([]string, error) {
	if err := ValidateInputPath(path); err != nil {
		return nil, err
	}
	if IsPDF(path) {
		imgs, err := ExtractPDFImages(path)
		if err != nil {
			return nil, err
		}
		var out []string
		for _, img := range imgs {
			txts, err := DecodeQRPayloadsFromImage(img)
			if err != nil {
				continue
			}
			out = append(out, txts...)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("no QR codes found in PDF images")
		}
		return out, nil
	}

	img, err := DecodeImageFile(path)
	if err != nil {
		return nil, err
	}
	txts, err := DecodeQRPayloadsFromImage(img)
	if err != nil {
		return nil, err
	}
	if len(txts) == 0 {
		return nil, fmt.Errorf("no QR codes found in image %s", filepath.Base(path))
	}
	return txts, nil
}


