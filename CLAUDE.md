# CLAUDE.md

## Project Overview

**Shamir Secret Sharing PDF Tool** — A Go GUI application that splits secrets into Shamir shares, encodes them as QR codes, and generates printable PDFs. Includes both encoding (splitting) and decoding (recovery) functionality.

Self-described as "vibe-coded" and in active development.

## Tech Stack

- **Language:** Go 1.24.3
- **GUI:** Fyne v2.7.1 (cross-platform, requires CGO)
- **PDF:** gofpdf
- **QR encode:** skip2/go-qrcode
- **QR decode:** makiuchi-d/gozxing (multi-QR support)
- **Secret sharing:** posener/sharedsecret
- **Crypto:** stdlib AES-256-GCM, HKDF-SHA256, compress/flate

## Repository Structure

```
.
├── main.go              # Entire application (single file, ~991 lines)
├── go.mod / go.sum      # Module definition and dependency lock
├── README.md            # User-facing documentation
├── .gitignore           # Ignores build outputs and OS/editor files
└── test/
    ├── README.md        # Test data description
    └── data/            # Sample PDFs and QR code PNGs for manual testing
```

This is a monolithic single-file application. All types, UI construction, cryptography, PDF generation, and QR handling live in `main.go`.

## Build & Run

```bash
# Install dependencies
go mod download

# Build
go build -o secret-sharing-tool .

# Run
./secret-sharing-tool
```

**Requirements:** Go 1.16+, CGO enabled (Fyne needs native bindings).

Build output names (`secret-sharing-tool`, `secret-sharing-pdf-tool`) are gitignored.

## Architecture (main.go)

### Key Types

- `ShareData` — Version, hex-encoded key share, base64 encrypted data
- `ShareChunk` — For splitting large shares across multiple QR codes (version, share/chunk indices, data)

### Major Functional Areas

| Area | Key Functions |
|------|--------------|
| Entry / GUI | `main()`, `createEncodeTab()`, `createDecodeTab()` |
| Cryptography | `deriveKeyFromSeed()`, `encryptAES()`, `decryptAES()` |
| Compression | `compressData()`, `decompressData()` |
| QR codes | `generateQRCode()`, `scanQRCodeFromImage()` |
| PDF | `generatePDF()` |
| Share parsing | `parseShareData()`, `extractShareString()`, `removeDuplicateShares()` |
| Chunking | `splitShareIntoChunks()`, `reconstructSharesFromChunks()` |

### Data Flow

**Encode:** plaintext -> flate compress -> AES-256-GCM encrypt (HKDF-derived key) -> Shamir split -> JSON shares -> QR codes -> PDF

**Decode:** QR scan / paste -> parse shares (reconstruct chunks if multi-part) -> Shamir recover -> AES decrypt -> decompress -> plaintext

### Version 2 Format

Shares are JSON with fields: `version`, `key_share` (hex), `encrypted_data` (base64). QR codes for shares > 500 bytes are split into up to 4 chunks.

## Testing

There are no automated tests (`go test` will find nothing). The `test/data/` directory contains:
- `test.pdf` / `new.pdf` — Generated PDFs for manual verification
- `test_0.png` through `test_5.png` — QR codes extracted from test.pdf
- `nonsense-qr.png` — Invalid QR for negative testing
- Large image files for edge case testing

## Code Conventions

- **Single-file structure:** All code in `main.go`
- **Error handling:** Errors are displayed in GUI status labels, not returned/propagated
- **No linter or formatter config:** Use standard `gofmt`
- **No CI/CD pipeline configured**

## Git Conventions

- Imperative commit messages: "Add feature", "Fix bug", "Update X"
- Short single-line messages (no body)
- Lowercase after the initial verb
- Examples: `Add compression; update the data version to 2`, `Add duplicate detection; remove camera button`

## Important Constraints

- Seed values must be < 2^127 - 1 (Shamir algorithm constraint from the sharedsecret library)
- Fyne requires CGO — won't build with `CGO_ENABLED=0`
- QR code size limit: shares > 500 bytes JSON are automatically split into multiple chunks
- The gozxing multi-reader has a fallback to single-reader if multi-QR detection fails
