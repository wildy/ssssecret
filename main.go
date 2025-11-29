package main

import (
	"bytes"
	"compress/flate"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	_ "image/jpeg"
	"io"
	"math/big"
	"regexp"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/jung-kurt/gofpdf"
	"github.com/makiuchi-d/gozxing"
	gozxingmultiqrcode "github.com/makiuchi-d/gozxing/multi/qrcode"
	gozxingqrcode "github.com/makiuchi-d/gozxing/qrcode"
	"github.com/posener/sharedsecret"
	"github.com/skip2/go-qrcode"
)

// ShareData contains both the key share and encrypted data for a single share
type ShareData struct {
	Version       string `json:"version"`
	KeyShare      string `json:"key_share"`
	EncryptedData string `json:"encrypted_data"`
}

// ShareChunk represents a chunk of a share when split across multiple QR codes
type ShareChunk struct {
	Version     string `json:"version"`
	ShareIndex  int    `json:"share_index"`  // Which share this belongs to (0-based)
	ChunkIndex  int    `json:"chunk_index"`  // Which chunk this is (0-based)
	TotalChunks int    `json:"total_chunks"` // Total number of chunks for this share
	Data        string `json:"data"`         // The chunk data (base64 encoded)
}

func main() {
	myApp := app.New()
	myWindow := myApp.NewWindow("Shamir Secret Sharing Tool")
	myWindow.Resize(fyne.NewSize(900, 700))

	// Create tabs
	tabs := container.NewAppTabs(
		container.NewTabItem("Encode", createEncodeTab(myWindow)),
		container.NewTabItem("Decode", createDecodeTab(myWindow)),
	)

	myWindow.SetContent(tabs)
	myWindow.ShowAndRun()
}

func createEncodeTab(myWindow fyne.Window) fyne.CanvasObject {
	// Input fields
	plaintextEntry := widget.NewMultiLineEntry()
	plaintextEntry.SetPlaceHolder("Enter your secret plaintext here...")
	plaintextEntry.Wrapping = fyne.TextWrapWord

	totalSharesEntry := widget.NewEntry()
	totalSharesEntry.SetText("5")
	totalSharesEntry.SetPlaceHolder("Total number of shares")

	thresholdEntry := widget.NewEntry()
	thresholdEntry.SetText("3")
	thresholdEntry.SetPlaceHolder("Minimum shares needed to recover")

	// Status label
	statusLabel := widget.NewLabel("Ready")
	statusLabel.Wrapping = fyne.TextWrapWord

	// Share display
	shareDisplay := widget.NewMultiLineEntry()
	shareDisplay.SetPlaceHolder("Generated shares will appear here...")
	shareDisplay.Wrapping = fyne.TextWrapWord
	shareDisplay.MultiLine = true

	var currentShares []ShareData
	var currentThreshold int

	// Generate shares button
	generateBtn := widget.NewButton("Generate Shares", func() {
		plaintext := plaintextEntry.Text
		if plaintext == "" {
			statusLabel.SetText("Error: Please enter a plaintext secret")
			return
		}

		totalShares, err := strconv.Atoi(totalSharesEntry.Text)
		if err != nil || totalShares < 2 {
			statusLabel.SetText("Error: Total shares must be at least 2")
			return
		}

		threshold, err := strconv.Atoi(thresholdEntry.Text)
		if err != nil || threshold < 2 {
			statusLabel.SetText("Error: Threshold must be at least 2")
			return
		}

		if threshold > totalShares {
			statusLabel.SetText("Error: Threshold cannot be greater than total shares")
			return
		}

		// Calculate the maximum allowed seed value (2^127 - 1)
		maxSecret := new(big.Int)
		maxSecret.Exp(big.NewInt(2), big.NewInt(127), nil)
		maxSecret.Sub(maxSecret, big.NewInt(1))

		// Generate a random seed (key material) for Shamir Secret Sharing
		// Keep regenerating until we get a seed that's less than 2^127 - 1
		var seed []byte
		var seedInt *big.Int
		const maxAttempts = 100 // Prevent infinite loop

		for attempt := 0; attempt < maxAttempts; attempt++ {
			seed = make([]byte, 16)
			if _, err := io.ReadFull(rand.Reader, seed); err != nil {
				statusLabel.SetText(fmt.Sprintf("Error generating seed: %v", err))
				return
			}

			// Convert seed to big.Int for Shamir Secret Sharing
			seedInt = new(big.Int)
			seedInt.SetBytes(seed)

			// Check if seed is within the limit
			if seedInt.Cmp(maxSecret) < 0 {
				break // Seed is valid, exit loop
			}
		}

		// If we couldn't generate a valid seed after max attempts, return error
		if seedInt.Cmp(maxSecret) >= 0 {
			statusLabel.SetText("Error: Failed to generate a valid seed after multiple attempts")
			return
		}

		// Compress the plaintext before encryption
		compressedData, err := compressData([]byte(plaintext))
		if err != nil {
			statusLabel.SetText(fmt.Sprintf("Error compressing secret: %v", err))
			return
		}

		// Derive the actual encryption key from the seed using HKDF-SHA256
		// K=HKDF-SHA256(seed=S, info="my app key", len=32 for AES-256)
		key, err := deriveKeyFromSeed(seed, 32)
		if err != nil {
			statusLabel.SetText(fmt.Sprintf("Error deriving key: %v", err))
			return
		}

		// Encrypt the compressed data using AES-256
		encryptedData, err := encryptAES(compressedData, key)
		if err != nil {
			statusLabel.SetText(fmt.Sprintf("Error encrypting secret: %v", err))
			return
		}

		// Generate seed shares using sharedsecret library
		seedShares := sharedsecret.Distribute(seedInt, int64(totalShares), int64(threshold))

		// Create share data with both seed share and encrypted data
		shareDataList := make([]ShareData, len(seedShares))
		var shareStrings []string
		for i, seedShare := range seedShares {
			// Convert seed share to hex for easier display
			seedShareBytes, err := seedShare.MarshalText()
			if err != nil {
				statusLabel.SetText(fmt.Sprintf("Error marshaling seed share: %v", err))
				return
			}
			seedShareHex := hex.EncodeToString(seedShareBytes)

			shareDataList[i] = ShareData{
				Version:       "2",
				KeyShare:      seedShareHex,
				EncryptedData: base64.StdEncoding.EncodeToString(encryptedData),
			}
			encPreview := shareDataList[i].EncryptedData
			if len(encPreview) > 20 {
				encPreview = encPreview[:20] + "..."
			}
			shareStrings = append(shareStrings, fmt.Sprintf("Share %d: Seed=%s, Encrypted=%s", i+1, seedShareHex, encPreview))
		}

		currentShares = shareDataList
		currentThreshold = threshold

		shareDisplay.SetText(strings.Join(shareStrings, "\n"))
		statusLabel.SetText(fmt.Sprintf("Generated %d shares (threshold: %d)", totalShares, threshold))
	})

	// Generate PDF button
	generatePDFBtn := widget.NewButton("Generate PDF with QR Codes", func() {
		if len(currentShares) == 0 {
			statusLabel.SetText("Error: Please generate shares first")
			return
		}

		// Show save dialog
		dialog.ShowFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil || writer == nil {
				return
			}
			defer writer.Close()

			err = generatePDF(currentShares, currentThreshold, writer)
			if err != nil {
				statusLabel.SetText(fmt.Sprintf("Error generating PDF: %v", err))
				dialog.ShowError(err, myWindow)
			} else {
				statusLabel.SetText("PDF generated successfully!")
				dialog.ShowInformation("Success", "PDF generated successfully!", myWindow)
			}
		}, myWindow)
	})

	// Layout
	form := container.NewVBox(
		widget.NewLabel("Secret Plaintext:"),
		plaintextEntry,
		widget.NewLabel("Configuration:"),
		container.NewGridWithColumns(2,
			container.NewVBox(
				widget.NewLabel("Total Shares:"),
				totalSharesEntry,
			),
			container.NewVBox(
				widget.NewLabel("Threshold:"),
				thresholdEntry,
			),
		),
		generateBtn,
		statusLabel,
		widget.NewLabel("Generated Shares:"),
		container.NewScroll(shareDisplay),
		generatePDFBtn,
	)

	return container.NewBorder(nil, nil, nil, nil, form)
}

func createDecodeTab(myWindow fyne.Window) fyne.CanvasObject {

	// Share input field
	shareInputEntry := widget.NewMultiLineEntry()
	shareInputEntry.SetPlaceHolder("Enter shares here, one per line...\nOr scan QR codes from files or camera")
	shareInputEntry.Wrapping = fyne.TextWrapWord

	// Status label
	decodeStatusLabel := widget.NewLabel("Ready")
	decodeStatusLabel.Wrapping = fyne.TextWrapWord

	// Recovered secret display
	recoveredSecretDisplay := widget.NewMultiLineEntry()
	recoveredSecretDisplay.SetPlaceHolder("Recovered secret will appear here...")
	recoveredSecretDisplay.Wrapping = fyne.TextWrapWord
	recoveredSecretDisplay.MultiLine = true

	// Function to check if a share already exists in the input
	shareExists := func(shareJSON string) bool {
		currentText := shareInputEntry.Text
		if currentText == "" {
			return false
		}

		// Parse the new share to get its KeyShare
		var newShare ShareData
		if err := json.Unmarshal([]byte(shareJSON), &newShare); err != nil {
			return false
		}

		// Parse existing shares and check for duplicates
		existingShares, err := parseShareData(currentText)
		if err != nil {
			return false
		}

		for _, existingShare := range existingShares {
			if existingShare.KeyShare == newShare.KeyShare {
				return true
			}
		}

		return false
	}

	// Function to add scanned shares to input (skipping duplicates)
	addSharesToInput := func(shareJSONs []string) {
		currentText := shareInputEntry.Text
		var newShares []string
		var duplicates int

		for _, shareJSON := range shareJSONs {
			if shareExists(shareJSON) {
				duplicates++
				continue
			}
			newShares = append(newShares, shareJSON)
		}

		// Add only non-duplicate shares
		for _, shareJSON := range newShares {
			if currentText != "" && !strings.HasSuffix(currentText, "\n") {
				currentText += "\n"
			}
			currentText += shareJSON
		}
		shareInputEntry.SetText(currentText)

		// Update status message
		if len(newShares) == 0 {
			if duplicates > 0 {
				decodeStatusLabel.SetText(fmt.Sprintf("All %d QR code(s) were duplicates", duplicates))
			} else {
				decodeStatusLabel.SetText("No valid shares found")
			}
		} else if duplicates > 0 {
			decodeStatusLabel.SetText(fmt.Sprintf("Added %d new share(s), skipped %d duplicate(s)", len(newShares), duplicates))
		} else if len(newShares) == 1 {
			decodeStatusLabel.SetText("QR code scanned successfully!")
		} else {
			decodeStatusLabel.SetText(fmt.Sprintf("Scanned %d QR codes successfully!", len(newShares)))
		}
	}

	// Recover secret button
	recoverBtn := widget.NewButton("Recover Secret", func() {
		shareText := shareInputEntry.Text
		if shareText == "" {
			decodeStatusLabel.SetText("Error: Please enter at least one share")
			return
		}

		// Parse share data from input (can be JSON or plain text)
		shareDataList, err := parseShareData(shareText)
		if err != nil {
			decodeStatusLabel.SetText(fmt.Sprintf("Error parsing shares: %v", err))
			recoveredSecretDisplay.SetText("")
			return
		}

		if len(shareDataList) == 0 {
			decodeStatusLabel.SetText("Error: No valid shares found")
			recoveredSecretDisplay.SetText("")
			return
		}

		// Remove duplicate shares (based on KeyShare)
		shareDataList = removeDuplicateShares(shareDataList)
		if len(shareDataList) == 0 {
			decodeStatusLabel.SetText("Error: No valid shares found after removing duplicates")
			recoveredSecretDisplay.SetText("")
			return
		}

		// Extract seed shares
		seedShares := make([]sharedsecret.Share, 0, len(shareDataList))
		var encryptedData string
		var version string
		for _, sd := range shareDataList {
			// Convert hex seed share back to bytes
			seedShareBytes, err := hex.DecodeString(sd.KeyShare)
			if err != nil {
				decodeStatusLabel.SetText(fmt.Sprintf("Error decoding hex seed share: %v", err))
				recoveredSecretDisplay.SetText("")
				return
			}

			var share sharedsecret.Share
			err = share.UnmarshalText(seedShareBytes)
			if err != nil {
				decodeStatusLabel.SetText(fmt.Sprintf("Error parsing seed share: %v", err))
				recoveredSecretDisplay.SetText("")
				return
			}
			seedShares = append(seedShares, share)
			// All shares should have the same encrypted data and version
			if encryptedData == "" {
				encryptedData = sd.EncryptedData
				version = sd.Version
			}
		}

		// Default to version 2 if version is not specified (for backward compatibility)
		if version == "" {
			version = "2"
		}

		// Recover the seed using sharedsecret library
		recoveredSeedInt := sharedsecret.Recover(seedShares...)
		recoveredSeed := recoveredSeedInt.Bytes()

		// Derive the actual encryption key from the recovered seed using HKDF-SHA256
		// K=HKDF-SHA256(seed=S, info="my app key", len=32 for AES-256)
		recoveredKey, err := deriveKeyFromSeed(recoveredSeed, 32)
		if err != nil {
			decodeStatusLabel.SetText(fmt.Sprintf("Error deriving key from seed: %v", err))
			recoveredSecretDisplay.SetText("")
			return
		}

		// Decode encrypted data
		encryptedBytes, err := base64.StdEncoding.DecodeString(encryptedData)
		if err != nil {
			decodeStatusLabel.SetText(fmt.Sprintf("Error decoding encrypted data: %v", err))
			recoveredSecretDisplay.SetText("")
			return
		}

		// Decrypt the data
		decryptedBytes, err := decryptAES(encryptedBytes, recoveredKey)
		if err != nil {
			decodeStatusLabel.SetText(fmt.Sprintf("Error decrypting secret: %v", err))
			recoveredSecretDisplay.SetText("")
			return
		}

		// Decompress the data if version is 2 or higher
		var plaintextBytes []byte
		if version == "2" || version == "" {
			plaintextBytes, err = decompressData(decryptedBytes)
			if err != nil {
				decodeStatusLabel.SetText(fmt.Sprintf("Error decompressing secret: %v", err))
				recoveredSecretDisplay.SetText("")
				return
			}
		} else {
			// Version 1: no compression
			plaintextBytes = decryptedBytes
		}

		recoveredSecretDisplay.SetText(string(plaintextBytes))
		decodeStatusLabel.SetText(fmt.Sprintf("Successfully recovered secret from %d share(s)", len(shareDataList)))
	})

	// Scan from file button
	scanFileBtn := widget.NewButton("Scan QR from File", func() {
		if myWindow == nil {
			decodeStatusLabel.SetText("Error: Window not available")
			return
		}
		dialog.ShowFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil || reader == nil {
				return
			}
			defer reader.Close()

			// Read image file
			img, _, err := image.Decode(reader)
			if err != nil {
				decodeStatusLabel.SetText(fmt.Sprintf("Error reading image: %v", err))
				return
			}

			// Decode QR codes (can be multiple)
			shareJSONs, err := scanQRCodeFromImage(img)
			if err != nil {
				decodeStatusLabel.SetText(fmt.Sprintf("Error scanning QR code(s): %v", err))
				return
			}

			addSharesToInput(shareJSONs)
		}, myWindow)
	})

	// Scan from camera button (opens file dialog for now, can be enhanced later)
	/* scanCameraBtn := widget.NewButton("Scan QR from Camera", func() {
		if myWindow == nil {
			decodeStatusLabel.SetText("Error: Window not available")
			return
		}
		// For now, we'll use file selection. Camera support can be added with gocv later
		dialog.ShowInformation("Camera Support", "Camera scanning will be available in a future update. Please use 'Scan QR from File' to select a captured image.", myWindow)
	}) */

	// Clear button
	clearBtn := widget.NewButton("Clear", func() {
		shareInputEntry.SetText("")
		recoveredSecretDisplay.SetText("")
		decodeStatusLabel.SetText("Ready")
	})

	// Layout
	form := container.NewVBox(
		widget.NewLabel("Enter Shares:"),
		widget.NewLabel("(One share per line. You can paste share strings or scan directly from image files)"),
		container.NewScroll(shareInputEntry),
		container.NewHBox(
			scanFileBtn,
			// scanCameraBtn,
			recoverBtn,
			clearBtn,
		),
		decodeStatusLabel,
		widget.NewLabel("Recovered Secret:"),
		container.NewScroll(recoveredSecretDisplay),
	)

	return container.NewBorder(nil, nil, nil, nil, form)
}

func parseShareData(input string) ([]ShareData, error) {
	lines := strings.Split(input, "\n")
	var shareDataList []ShareData

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Try to parse as JSON first
		var shareData ShareData
		if err := json.Unmarshal([]byte(line), &shareData); err == nil {
			if shareData.KeyShare != "" && shareData.EncryptedData != "" {
				shareDataList = append(shareDataList, shareData)
				continue
			}
		}

		// If not JSON, try to extract from old format or other formats
		// This is for backward compatibility
		shareStr := extractShareString(line)
		if shareStr != "" {
			// Old format - we need encrypted data, but we don't have it
			// Skip for now, or we could try to find it in the same line
			continue
		}
	}

	return shareDataList, nil
}

// removeDuplicateShares removes duplicate shares based on KeyShare field
func removeDuplicateShares(shares []ShareData) []ShareData {
	seen := make(map[string]bool)
	var uniqueShares []ShareData

	for _, share := range shares {
		// Use KeyShare as the unique identifier
		if !seen[share.KeyShare] {
			seen[share.KeyShare] = true
			uniqueShares = append(uniqueShares, share)
		}
	}

	return uniqueShares
}

func extractShareString(line string) string {
	// Look for patterns like "Share X: (1,123)" or just "(1,123)"
	// The share format from String() method is typically like "(x,y)"

	// Try to find the share data in parentheses
	start := strings.Index(line, "(")
	end := strings.LastIndex(line, ")")
	if start != -1 && end != -1 && end > start {
		return line[start : end+1]
	}

	// If no parentheses, try to find after colon
	if idx := strings.Index(line, ":"); idx != -1 {
		part := strings.TrimSpace(line[idx+1:])
		if strings.HasPrefix(part, "(") {
			return part
		}
	}

	return ""
}

func generateQRCode(data string) ([]byte, error) {
	qrImage, err := qrcode.Encode(data, qrcode.Medium, -1)
	if err != nil {
		return nil, fmt.Errorf("failed to generate QR code: %v", err)
	}
	return qrImage, nil
}

func generatePDF(shares []ShareData, threshold int, writer fyne.URIWriteCloser) error {
	pdf := gofpdf.New("P", "mm", "A4", "")
	pdf.SetTitle("Shamir Secret Sharing Shares", false)
	pdf.SetAuthor("Secret Sharing Tool", false)

	// Add title page
	pdf.AddPage()
	pdf.SetFont("Arial", "B", 16)
	pdf.Cell(40, 10, "Shamir Secret Sharing")
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 12)
	pdf.Cell(40, 10, fmt.Sprintf("Total Shares: %d", len(shares)))
	pdf.Ln(5)
	pdf.Cell(40, 10, fmt.Sprintf("Threshold: %d shares required to recover secret", threshold))
	pdf.Ln(10)
	pdf.SetFont("Arial", "", 10)
	pdf.Cell(40, 10, "Each share below contains a QR code with key share and encrypted data.")
	pdf.Ln(10)
	pdf.Cell(40, 10, "Keep shares secure and distribute them to trusted parties.")
	pdf.Ln(20)

	// Generate QR codes and add pages for each share
	for i, share := range shares {
		// Create JSON representation of share data
		shareJSON, err := json.Marshal(share)
		if err != nil {
			return fmt.Errorf("failed to marshal share data: %v", err)
		}

		// Check if share data is too large for a single QR code (limit ~2000 chars for medium error correction)
		const maxQRSize = 500
		shareJSONStr := string(shareJSON)

		if len(shareJSONStr) <= maxQRSize {
			// Single QR code - use existing logic

			qrImage, err := generateQRCode(shareJSONStr)
			if err != nil {
				return fmt.Errorf("failed to generate QR code: %v", err)
			}

			// Add new page for each share
			pdf.AddPage()
			pdf.SetFont("Arial", "B", 14)
			pdf.Cell(40, 10, fmt.Sprintf("Share %d of %d", i+1, len(shares)))
			pdf.Cell(40, 10, fmt.Sprintf("Version: %s", share.Version))
			pdf.Ln(10)

			// Add QR code image
			imageName := fmt.Sprintf("qr_%d", i)
			pdf.RegisterImageOptionsReader(imageName, gofpdf.ImageOptions{ImageType: "PNG"}, bytes.NewReader(qrImage))
			pdf.ImageOptions(imageName, 60, 40, 90, 90, false, gofpdf.ImageOptions{}, 0, "")
		} else {
			// Split into multiple QR codes (up to 4)
			chunks := splitShareIntoChunks(share, i, maxQRSize)
			for chunkIdx, chunk := range chunks {
				chunkJSON, err := json.Marshal(chunk)
				if err != nil {
					return fmt.Errorf("failed to marshal chunk: %v", err)
				}

				qrImage, err := generateQRCode(string(chunkJSON))
				if err != nil {
					return fmt.Errorf("failed to generate QR code: %v", err)
				}

				// Add new page for each chunk
				pdf.AddPage()
				pdf.SetFont("Arial", "B", 14)
				pdf.Cell(40, 10, fmt.Sprintf("Share %d of %d - Part %d of %d", i+1, len(shares), chunkIdx+1, len(chunks)))
				pdf.Cell(40, 10, fmt.Sprintf("Version: %s", share.Version))
				pdf.Ln(10)

				// Add QR code image
				imageName := fmt.Sprintf("qr_%d_%d", i, chunkIdx)
				pdf.RegisterImageOptionsReader(imageName, gofpdf.ImageOptions{ImageType: "PNG"}, bytes.NewReader(qrImage))
				pdf.ImageOptions(imageName, 60, 40, 90, 90, false, gofpdf.ImageOptions{}, 0, "")
			}
		}

		// Add share data text (only for single QR code shares)
		if len(shareJSONStr) <= maxQRSize {
			pdf.SetFont("Arial", "", 12)
			pdf.SetXY(20, 140)
			pdf.Cell(40, 10, "Key Share:")
			pdf.Ln(8)
			pdf.SetFont("Courier", "", 9)
			pdf.Cell(40, 10, share.KeyShare)
			pdf.Ln(10)
			pdf.SetFont("Arial", "", 12)
			pdf.Cell(40, 10, "Encrypted Data (preview):")
			pdf.Ln(8)
			pdf.SetFont("Courier", "", 8)
			encPreview := share.EncryptedData
			if len(encPreview) > 50 {
				encPreview = encPreview[:50] + "..."
			}
			pdf.Cell(40, 10, encPreview)
			pdf.Ln(15)
			pdf.SetFont("Arial", "", 10)
			pdf.Cell(40, 10, "Scan the QR code above to recover the secret.")
		} else {
			// For multi-part shares, show instructions
			pdf.SetFont("Arial", "", 12)
			pdf.SetXY(20, 140)
			pdf.Cell(40, 10, "This share is split across multiple QR codes.")
			pdf.Ln(8)
			pdf.Cell(40, 10, "Scan all parts to reconstruct this share.")
		}
	}

	// Write PDF to file
	err := pdf.Output(writer)
	return err
}

// deriveKeyFromSeed derives an encryption key from seed material using HKDF-SHA256
// K=HKDF-SHA256(seed=S, info="my app key", len=keyLen)
func deriveKeyFromSeed(seed []byte, keyLen int) ([]byte, error) {
	// Use HKDF.Key which combines Extract and Expand
	// HKDF.Key(hash, secret, salt, info, keyLength)
	key, err := hkdf.Key(sha256.New, seed, nil, "my app key", keyLen)
	if err != nil {
		return nil, fmt.Errorf("failed to derive key: %w", err)
	}

	return key, nil
}

// encryptAES encrypts data using AES-256 in GCM mode
func encryptAES(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Generate a random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decryptAES decrypts data using AES-256 in GCM mode
func decryptAES(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Extract nonce
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt and verify
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

// splitShareIntoChunks splits a share into multiple chunks if it's too large for a single QR code
// Returns up to 4 chunks
func splitShareIntoChunks(share ShareData, shareIndex int, maxChunkSize int) []ShareChunk {
	// Create JSON representation of the share
	shareJSON, err := json.Marshal(share)
	if err != nil {
		// If marshaling fails, return empty chunks
		return []ShareChunk{}
	}

	shareJSONStr := string(shareJSON)

	// Calculate how many chunks we need (up to 4)
	// Account for chunk metadata overhead (~100 chars for JSON structure)
	availableSize := maxChunkSize - 100
	dataLen := len(shareJSONStr)
	numChunks := (dataLen + availableSize - 1) / availableSize // Ceiling division
	if numChunks > 4 {
		numChunks = 4
	}

	chunkSize := (dataLen + numChunks - 1) / numChunks // Divide evenly
	chunks := make([]ShareChunk, 0, numChunks)

	for i := 0; i < numChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		if end > dataLen {
			end = dataLen
		}
		if start >= dataLen {
			break
		}

		// Encode chunk data as base64 for safe transmission
		chunkData := base64.StdEncoding.EncodeToString([]byte(shareJSONStr[start:end]))

		chunk := ShareChunk{
			Version:     "2",
			ShareIndex:  shareIndex,
			ChunkIndex:  i,
			TotalChunks: numChunks,
			Data:        chunkData,
		}
		chunks = append(chunks, chunk)
	}

	return chunks
}

// scanQRCodeFromImage scans QR codes from an image and returns all decoded JSON strings
func scanQRCodeFromImage(img image.Image) ([]string, error) {
	// Convert image to binary bitmap
	bitmap, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return nil, fmt.Errorf("failed to create bitmap: %w", err)
	}

	// Create QR code multi-reader to detect multiple QR codes
	multiReader := gozxingmultiqrcode.NewQRCodeMultiReader()

	// Try to decode multiple QR codes
	decoderHints := map[gozxing.DecodeHintType]interface{}{
		gozxing.DecodeHintType_TRY_HARDER:       true,
		gozxing.DecodeHintType_POSSIBLE_FORMATS: []gozxing.BarcodeFormat{gozxing.BarcodeFormat_QR_CODE},
	}

	results, err := multiReader.DecodeMultiple(bitmap, decoderHints)
	if err != nil {
		// If multi-reader fails, try single reader as fallback
		singleReader := gozxingqrcode.NewQRCodeReader()
		result, singleErr := singleReader.Decode(bitmap, decoderHints)
		if singleErr != nil {
			return nil, fmt.Errorf("failed to decode QR code(s): %w", err)
		}
		results = []*gozxing.Result{result}
	}

	if len(results) == 0 {
		return nil, fmt.Errorf("no QR codes found in image")
	}

	// Validate and collect valid share JSON strings or chunks
	versionRe := regexp.MustCompile(`^{"version"`)
	chunkRe := regexp.MustCompile(`{"share_index"`)
	var validShares []string
	var chunks []ShareChunk

	for _, result := range results {
		text := result.GetText()
		if !versionRe.MatchString(text) {
			continue
		}

		if chunkRe.MatchString(text) {
			// Share chunk - parse and store
			var chunk ShareChunk
			if err := json.Unmarshal([]byte(text), &chunk); err == nil {
				chunks = append(chunks, chunk)
			}
		} else {
			// Regular share
			validShares = append(validShares, text)
		}
	}

	// Reconstruct shares from chunks
	if len(chunks) > 0 {
		reconstructedShares, err := reconstructSharesFromChunks(chunks)
		if err != nil {
			return nil, fmt.Errorf("failed to reconstruct shares from chunks: %w", err)
		}
		validShares = append(validShares, reconstructedShares...)
	}

	if len(validShares) == 0 {
		return nil, fmt.Errorf("no valid share QR codes found (found %d QR code(s) but none match expected format)", len(results))
	}

	return validShares, nil
}

// reconstructSharesFromChunks reconstructs ShareData from chunks
func reconstructSharesFromChunks(chunks []ShareChunk) ([]string, error) {
	// Group chunks by share index
	shareChunks := make(map[int][]ShareChunk)
	for _, chunk := range chunks {
		shareChunks[chunk.ShareIndex] = append(shareChunks[chunk.ShareIndex], chunk)
	}

	var reconstructedShares []string

	// Reconstruct each share
	for _, chunksForShare := range shareChunks {
		// Sort chunks by chunk index
		for i := 0; i < len(chunksForShare)-1; i++ {
			for j := i + 1; j < len(chunksForShare); j++ {
				if chunksForShare[i].ChunkIndex > chunksForShare[j].ChunkIndex {
					chunksForShare[i], chunksForShare[j] = chunksForShare[j], chunksForShare[i]
				}
			}
		}

		// Verify we have all chunks
		if len(chunksForShare) != chunksForShare[0].TotalChunks {
			continue // Skip incomplete shares
		}

		// Reconstruct the full data by decoding each chunk and concatenating
		var fullData strings.Builder
		for _, chunk := range chunksForShare {
			// Decode chunk from base64
			decodedChunk, err := base64.StdEncoding.DecodeString(chunk.Data)
			if err != nil {
				continue // Skip invalid chunk
			}
			fullData.Write(decodedChunk)
		}

		// Parse the reconstructed JSON as ShareData
		var shareData ShareData
		if err := json.Unmarshal([]byte(fullData.String()), &shareData); err != nil {
			continue // Skip invalid JSON
		}

		// Convert back to JSON string
		shareJSON, err := json.Marshal(shareData)
		if err != nil {
			continue
		}

		reconstructedShares = append(reconstructedShares, string(shareJSON))
	}

	return reconstructedShares, nil
}

// compressData compresses data using flate compression
func compressData(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	writer, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, fmt.Errorf("failed to create flate writer: %w", err)
	}

	_, err = writer.Write(data)
	if err != nil {
		writer.Close()
		return nil, fmt.Errorf("failed to compress data: %w", err)
	}

	err = writer.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to finalize compression: %w", err)
	}

	return buf.Bytes(), nil
}

// decompressData decompresses data using flate decompression
func decompressData(compressedData []byte) ([]byte, error) {
	reader := flate.NewReader(bytes.NewReader(compressedData))
	defer reader.Close()

	var buf bytes.Buffer
	_, err := buf.ReadFrom(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress data: %w", err)
	}

	return buf.Bytes(), nil
}
