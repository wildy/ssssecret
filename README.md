# Shamir Secret Sharing PDF Tool


A Golang application using Fyne GUI that generates Shamir Secret Sharing codes from plaintext input and creates printable PDFs with QR codes for each share.

**Disclaimer:** This is currently vibe-coded, and my next task (as part of trying to learn some Go) is to clean up the code.

## Features

- **Tabbed Interface**: Two separate tabs for encoding and decoding
- **Encode Tab**: 
  - Plaintext Input: Enter any text secret that needs to be shared securely
  - Configurable Sharing: Set the total number of shares and the threshold (minimum shares needed to recover)
  - QR Code Generation: Each share is encoded as a QR code for easy scanning
  - PDF Export: Generate a printable PDF document with QR codes and share data
- **Decode Tab**:
  - Share Input: Paste or enter shares to recover the original secret
  - Secret Recovery: Automatically recovers the plaintext from the provided shares

## Requirements

- Go 1.16 or later
- CGO enabled (required for Fyne)

## Installation

1. Clone or download this repository
2. Install dependencies:
   ```bash
   go mod download
   ```

## Building

```bash
go build -o secret-sharing-tool .
```

## Usage

### Encoding a Secret (Encode Tab)

1. Run the application:
   ```bash
   ./secret-sharing-tool
   ```

2. Make sure you're on the **Encode** tab

3. Enter your secret plaintext in the text area

4. Configure the sharing parameters:
   - **Total Shares**: Number of shares to generate (minimum 2)
   - **Threshold**: Minimum number of shares needed to recover the secret (must be ≤ total shares)

5. Click "Generate Shares" to create the shares

6. Review the generated shares in the display area

7. Click "Generate PDF with QR Codes" to create a printable PDF document

8. Save the PDF to your desired location

### Decoding Shares (Decode Tab)

1. Switch to the **Decode** tab

2. Enter or paste the shares you want to use to recover the secret
   - You can paste shares one per line
   - The format can be either just the share data (e.g., `(1,123456789)`) or with labels (e.g., `Share 1: (1,123456789)`)
   - You need at least the threshold number of shares to recover the secret

3. Click "Recover Secret" to decode the shares

4. The recovered plaintext will appear in the output area

5. Use the "Clear" button to reset the input and output fields

## How It Works

This application uses the [github.com/posener/sharedsecret](https://github.com/posener/sharedsecret) library, which implements Shamir's Secret Sharing algorithm. The secret is split into multiple shares such that:

- Any subset of shares equal to or greater than the threshold can recover the original secret
- Any subset smaller than the threshold cannot recover the secret

Each share is:
- Encoded as a QR code for easy scanning
- Included in the PDF with both the QR code and the share data as text
- Safe to distribute to different parties

## Recovering the Secret

The application includes a built-in decode tab that makes it easy to recover secrets. Simply:

1. Collect at least the threshold number of shares
2. Switch to the **Decode** tab
3. Paste the shares (one per line)
4. Click "Recover Secret"

The application uses the `sharedsecret.Recover()` function internally to reconstruct the original secret from the provided shares.

## Libraries Used

- [Fyne](https://fyne.io/) - Cross-platform GUI framework
- [github.com/posener/sharedsecret](https://github.com/posener/sharedsecret) - Shamir's Secret Sharing implementation
- [github.com/skip2/go-qrcode](https://github.com/skip2/go-qrcode) - QR code generation
- [github.com/jung-kurt/gofpdf](https://github.com/jung-kurt/gofpdf) - PDF generation

## License

This project uses libraries with various licenses. Please refer to the individual library licenses for details.

