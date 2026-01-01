package roundtrip

import (
	"bytes"
	"testing"

	"github.com/hashicorp/vault/shamir"

	"github.com/wildy/ssssecret/internal/qrpayload"

	"github.com/wildy/ssssecret/internal/cryptox"
)

func TestRoundTrip_SplitCombine_EncryptDecrypt(t *testing.T) {
	secret := bytes.Repeat([]byte("hello-world-"), 2000) // 24kB
	docID := "TESTDOCID1234"

	x, err := cryptox.GenerateX()
	if err != nil {
		t.Fatal(err)
	}
	salt, err := cryptox.RandomBytes(cryptox.SaltSizeBytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cryptox.DeriveAES256Key(x, salt)
	if err != nil {
		t.Fatal(err)
	}
	env, err := cryptox.EncryptAES256GCM(secret, key, []byte(docID))
	if err != nil {
		t.Fatal(err)
	}

	n, threshold := 5, 3
	shares, err := shamir.Split(x, n, threshold)
	if err != nil {
		t.Fatal(err)
	}
	x2, err := shamir.Combine([][]byte{shares[0], shares[2], shares[4]})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x, x2) {
		t.Fatalf("reconstructed X mismatch")
	}

	key2, err := cryptox.DeriveAES256Key(x2, salt)
	if err != nil {
		t.Fatal(err)
	}
	plain2, err := cryptox.DecryptAES256GCM(env, key2, []byte(docID))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, plain2) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestRoundTrip_CompressEncryptDecryptDecompress(t *testing.T) {
	secret := bytes.Repeat([]byte("hello-world-"), 4000) // 48kB, compressible
	docID := "TESTDOCID5678"

	x, err := cryptox.GenerateX()
	if err != nil {
		t.Fatal(err)
	}
	salt, err := cryptox.RandomBytes(cryptox.SaltSizeBytes)
	if err != nil {
		t.Fatal(err)
	}
	key, err := cryptox.DeriveAES256Key(x, salt)
	if err != nil {
		t.Fatal(err)
	}

	compressed, err := cryptox.CompressGzip(secret)
	if err != nil {
		t.Fatal(err)
	}

	env, err := cryptox.EncryptAES256GCM(compressed, key, []byte(docID))
	if err != nil {
		t.Fatal(err)
	}
	compressed2, err := cryptox.DecryptAES256GCM(env, key, []byte(docID))
	if err != nil {
		t.Fatal(err)
	}
	secret2, err := cryptox.DecompressGzip(compressed2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(secret, secret2) {
		t.Fatalf("decompressed plaintext mismatch")
	}
}

func TestSplitBytes_Reassemble(t *testing.T) {
	b := bytes.Repeat([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, 777) // 7770
	chunks, err := qrpayload.SplitBytes(b, 800)
	if err != nil {
		t.Fatal(err)
	}
	var out []byte
	for _, c := range chunks {
		out = append(out, c...)
	}
	if !bytes.Equal(b, out) {
		t.Fatalf("reassembly mismatch")
	}
}


