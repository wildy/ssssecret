package qrpayload

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
)

const Version = 1

type Type string

const (
	TypeCipherChunk Type = "cipher"
	TypeShare       Type = "share"
)

type Common struct {
	V    int    `json:"v"`
	Type Type   `json:"type"`
	Doc  string `json:"doc"`
}

type CipherChunkV1 struct {
	Common

	KDF  string `json:"kdf"`            // "HKDF-SHA256"
	AEAD string `json:"aead"`           // "AES-256-GCM"
	Comp string `json:"comp,omitempty"` // "", "gzip"

	N int `json:"n"`
	T int `json:"t"`

	SaltB64  string `json:"salt_b64"`
	NonceB64 string `json:"nonce_b64"`

	ChunkIndex int    `json:"chunk_index"` // 1-based
	ChunkTotal int    `json:"chunk_total"`
	DataB64    string `json:"data_b64"` // ciphertext chunk
}

type ShareV1 struct {
	Common

	N int `json:"n"`
	T int `json:"t"`

	ShareB64 string `json:"share_b64"`
}

func NewDocID() (string, error) {
	// 10 random bytes => 16 base32 chars (no padding)
	b := make([]byte, 10)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b), nil
}

func MarshalJSON(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func B64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func UnmarshalType(doc string) (Type, error) {
	var c Common
	if err := json.Unmarshal([]byte(doc), &c); err != nil {
		return "", err
	}
	if c.V != Version {
		return "", fmt.Errorf("unsupported payload version %d", c.V)
	}
	return c.Type, nil
}
