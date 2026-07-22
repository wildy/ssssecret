# CLAUDE.md

## Project Overview

**Shamir Secret Sharing PDF Tool** — A Go GUI application that splits secrets into Shamir shares, encodes them as QR codes, and generates printable PDFs. Includes both encoding (splitting) and decoding (recovery) functionality.

## Tech Stack

- **Language:** Go 1.25.3
- **GUI:** Fyne v2.7.1 (cross-platform, requires CGO)
- **PDF generation:** jung-kurt/gofpdf
- **PDF extraction:** pdfcpu/pdfcpu
- **QR encode:** skip2/go-qrcode
- **QR decode:** makiuchi-d/gozxing (multi-QR, multi-orientation)
- **Secret sharing:** hashicorp/vault/shamir (GF(256))
- **Crypto:** stdlib AES-256-GCM, HKDF-SHA256 (golang.org/x/crypto), gzip compression

## Repository Structure

```
.
├── main.go                 # Entry point — creates Fyne window, delegates to appui
├── go.mod / go.sum
├── README.md
├── CLAUDE.md
├── .gitignore
└── internal/
    ├── appui/              # GUI tabs (Encrypt/Decrypt) and orchestration
    │   ├── ui.go
    │   └── ui_test.go
    ├── cryptox/            # AES-256-GCM encrypt/decrypt, HKDF key derivation, gzip
    │   ├── cryptox.go
    │   └── compress.go
    ├── qrpayload/          # QR payload types (CipherChunkV1, ShareV1), JSON marshal
    │   ├── payload.go
    │   └── chunking.go
    ├── inputscan/          # File input: PDF image extraction, QR decoding
    │   ├── scan.go
    │   ├── qr_decode.go
    │   ├── qr_decode_test.go
    │   ├── pdf_images.go
    │   └── images.go
    ├── pdfgen/             # PDF rendering with QR codes (grid + full-page layouts)
    │   └── pdfgen.go
    ├── recover/            # Payload parsing, grouping by doc ID, Shamir combine, decrypt
    │   └── recover.go
    └── roundtrip/          # Integration tests (encrypt → split → combine → decrypt)
        └── roundtrip_test.go
```

## Build & Run

```bash
go mod download
go build -o ssssecret .
./ssssecret
```

**Requirements:** CGO enabled (Fyne needs native bindings).

## Testing

```bash
go test ./internal/...
```

Tests exist in four packages:
- `appui/ui_test.go` — Unit tests for UI helpers (parseIntInRange, previewBytes, showRecovered, shortenPaths)
- `inputscan/qr_decode_test.go` — QR decode from generated image, rotate90 bounds handling
- `inputscan/tiff_decode_test.go` — CMYK TIFF decode (pdfcpu writes CMYK image XObjects as TIFF)
- `recover/recover_test.go` — Duplicate-share dedup, corrupt-chunk metadata handling
- `roundtrip/roundtrip_test.go` — Full encrypt/compress/split/combine/decrypt cycle
- `roundtrip/pdf_roundtrip_test.go` — End-to-end encode → PDF → scan → recover
- `roundtrip/qr_capacity_test.go` — Max chunk size fits a QR and decodes at default pixel size

## Architecture

### Package Responsibilities

| Package | Role |
|---------|------|
| `appui` | Fyne GUI (Encrypt/Decrypt tabs), orchestrates all other packages |
| `cryptox` | `GenerateX()`, `DeriveAES256Key()`, `EncryptAES256GCM()`, `DecryptAES256GCM()`, gzip compress/decompress |
| `qrpayload` | Payload types (`CipherChunkV1`, `ShareV1`), JSON marshaling, doc ID generation, byte chunking |
| `inputscan` | `ScanFile()` routes PDFs/images → extract images → decode QR codes (4 rotations, dedup) |
| `pdfgen` | `RenderCiphertextThenShares()` — cipher chunks in 2×3 grid, shares one per full page |
| `recover` | `ParseAndGroup()` groups payloads by doc ID, `RecoverSecret()` runs Shamir combine → AES decrypt → decompress |
| `roundtrip` | Integration tests only |

### Data Flow

**Encode:** secret → gzip compress → generate random 32-byte X → derive AES key via HKDF-SHA256 → AES-256-GCM encrypt (doc ID as AAD) → split ciphertext into chunks → Shamir split X into n shares → JSON payloads → QR codes → PDF

**Decode:** PDF/images → extract images → decode QR codes (multi-orientation) → parse JSON → group by doc ID → validate chunks + threshold shares → Shamir combine → derive AES key → decrypt → decompress → plaintext

### Key Types

- `cryptox.AEADEnvelope` — Salt, Nonce, Ciphertext
- `qrpayload.CipherChunkV1` — Encryption metadata + ciphertext chunk + chunk index/total
- `qrpayload.ShareV1` — Base64-encoded Shamir share
- `recover.Grouped` — Per-document accumulated payloads (cipher params, chunks, shares)

## Code Conventions

- Error handling: errors displayed in GUI status labels
- Formatting: standard `gofmt`
- No CI/CD pipeline

## Git Conventions

- Imperative commit messages: "Add feature", "Fix bug", "Update X"
- Short single-line messages (no body), lowercase after initial verb
- Examples: `Add compression; update the data version to 2`, `Total rewrite: let's use this version as base instead`

## Important Constraints

- Fyne requires CGO — won't build with `CGO_ENABLED=0`
- Shamir splitting uses hashicorp/vault/shamir which operates over GF(256); X is always 32 bytes
- Default ciphertext chunk size: 1501 bytes; UI caps it at `qrpayload.MaxChunkSize` (1550) so every chunk payload fits a version-40 QR at Medium ECC (2331 bytes)
- QR PNGs render at 1536px (`pdfgen.DefaultOptions`) — gozxing cannot decode max-density QR codes below ~1536px, so do not lower this
- QR decode tries 4 rotations (0°, 90°, 180°, 270°) with deduplication
- QR decode uses gozxing's multi-QR reader only; there is deliberately no single-reader fallback (the single reader performs worse on dense codes)
- `os.MkdirTemp` patterns must not contain `/` — a module-rename find/replace once broke PDF scanning by inserting the module path into the temp-dir pattern
