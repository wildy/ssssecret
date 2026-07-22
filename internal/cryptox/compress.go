package cryptox

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

// CompressGzip compresses b using gzip (default level).
func CompressGzip(b []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func DecompressGzip(b []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	out, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	// Basic sanity: gzip can expand; callers should still enforce their own limits.
	if out == nil {
		return nil, fmt.Errorf("gzip decompressed to nil")
	}
	return out, nil
}
