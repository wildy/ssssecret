package qrpayload

import "fmt"

// MaxChunkSize is the largest ciphertext chunk that still fits in one QR code:
// a version-40 QR at Medium ECC holds 2331 bytes, and a chunk of C bytes costs
// ceil(C/3)*4 base64 chars plus ~240 chars of CipherChunkV1 JSON framing.
const MaxChunkSize = 1550

// SplitBytes splits b into chunks of at most chunkSize bytes.
func SplitBytes(b []byte, chunkSize int) ([][]byte, error) {
	if chunkSize <= 0 {
		return nil, fmt.Errorf("chunkSize must be > 0")
	}
	if len(b) == 0 {
		return [][]byte{[]byte{}}, nil
	}
	var out [][]byte
	for i := 0; i < len(b); i += chunkSize {
		j := i + chunkSize
		if j > len(b) {
			j = len(b)
		}
		out = append(out, b[i:j])
	}
	return out, nil
}
