package qrpayload

import "fmt"

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


