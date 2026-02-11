package inputscan

import (
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"os"
	"path/filepath"
	"strings"

	_ "golang.org/x/image/tiff"
)

func DecodeImageFile(path string) (image.Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	img, _, err := image.Decode(f)
	if err != nil {
		return nil, err
	}
	return img, nil
}

func IsPDF(path string) bool {
	return strings.EqualFold(filepath.Ext(path), ".pdf")
}

func IsImage(path string) bool {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".png", ".jpg", ".jpeg", ".gif", ".tif", ".tiff":
		return true
	default:
		return false
	}
}

func ValidateInputPath(path string) error {
	if path == "" {
		return fmt.Errorf("path is empty")
	}
	if !IsPDF(path) && !IsImage(path) {
		return fmt.Errorf("unsupported input type: %s", filepath.Ext(path))
	}
	return nil
}


