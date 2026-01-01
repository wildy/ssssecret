# github.com/wildy/ssssecret (Shamir + AES-256 + QR + PDF)

Desktop tool (Go + Fyne) to share a large secret on paper:

- Generate a random 32-byte value \(X\)
- Derive an AES-256 key from \(X\) using HKDF-SHA256
- **Gzip-compress** the secret (to reduce QR count), then encrypt using AES-256-GCM
- Split \(X\) into \(n\) Shamir shares with threshold \(t\)
- Render **ciphertext QR chunks** + **share QRs** into a printable PDF

## Why `github.com/hashicorp/vault/shamir`?

This project uses **HashiCorp Vault's** Shamir implementation:

- Import: `github.com/hashicorp/vault/shamir`
- API: `shamir.Split(secret, parts, threshold)` and `shamir.Combine(shares)`
- Note: Vault's implementation operates over GF(256), which is perfect here because we only split **32 bytes** (the random \(X\)), not the whole user secret.

## Run

```bash
go run .
```

## Output format (QR payloads)

The PDF contains 2 QR types (JSON):

- **Cipher chunks**: all pages labeled `CIPHERTEXT i/N` (must collect *all*)
- **Shares**: pages labeled `SHARE j` (collect *t of n*)

With those, you can reconstruct \(X\) (from shares), derive the AES key, and decrypt the ciphertext.


