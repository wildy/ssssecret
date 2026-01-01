package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const (
	XSizeBytes    = 32
	SaltSizeBytes = 16
	NonceSize     = 12 // AES-GCM standard nonce size
)

var hkdfInfo = []byte("github.com/wildy/ssssecret aes-256 key v1")

func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

func GenerateX() ([]byte, error) {
	return RandomBytes(XSizeBytes)
}

// DeriveAES256Key derives a 32-byte key from X using HKDF-SHA256.
func DeriveAES256Key(x, salt []byte) ([]byte, error) {
	if len(x) == 0 {
		return nil, fmt.Errorf("x must not be empty")
	}
	if len(salt) == 0 {
		return nil, fmt.Errorf("salt must not be empty")
	}
	r := hkdf.New(sha256.New, x, salt, hkdfInfo)
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, err
	}
	return key, nil
}

type AEADEnvelope struct {
	Salt       []byte
	Nonce      []byte
	Ciphertext []byte
}

func EncryptAES256GCM(plaintext, key, aad []byte) (*AEADEnvelope, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 key must be 32 bytes, got %d", len(key))
	}
	nonce, err := RandomBytes(NonceSize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ct := gcm.Seal(nil, nonce, plaintext, aad)
	return &AEADEnvelope{Nonce: nonce, Ciphertext: ct}, nil
}

func DecryptAES256GCM(env *AEADEnvelope, key, aad []byte) ([]byte, error) {
	if env == nil {
		return nil, fmt.Errorf("env is nil")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("AES-256 key must be 32 bytes, got %d", len(key))
	}
	if len(env.Nonce) != NonceSize {
		return nil, fmt.Errorf("nonce must be %d bytes, got %d", NonceSize, len(env.Nonce))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, env.Nonce, env.Ciphertext, aad)
}
