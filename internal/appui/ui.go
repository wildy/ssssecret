package appui

import (
	"bytes"
	"fmt"
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
	"github.com/hashicorp/vault/shamir"

	"github.com/wildy/ssssecret/internal/inputscan"
	"github.com/wildy/ssssecret/internal/pdfgen"
	"github.com/wildy/ssssecret/internal/qrpayload"
	"github.com/wildy/ssssecret/internal/recover"

	"github.com/wildy/ssssecret/internal/cryptox"
)

const defaultChunkSize = 1501 // bytes of ciphertext per QR (before base64/JSON overhead)

func DefaultWindowSize() fyne.Size { return fyne.NewSize(860, 680) }

func Build(w fyne.Window) (fyne.CanvasObject, error) {
	encTab, err := buildEncryptTab(w)
	if err != nil {
		return nil, err
	}
	decTab, err := buildDecryptTab(w)
	if err != nil {
		return nil, err
	}
	return container.NewAppTabs(
		container.NewTabItem("Encrypt", encTab),
		container.NewTabItem("Decrypt", decTab),
	), nil
}

func buildEncryptTab(w fyne.Window) (fyne.CanvasObject, error) {
	var secretBytes []byte
	fileLoaded := false
	settingPreview := false

	secretEntry := widget.NewMultiLineEntry()
	secretEntry.SetPlaceHolder("Paste or type your secret here (or load a file).")
	secretEntry.Wrapping = fyne.TextWrapWord
	secretEntry.OnChanged = func(_ string) {
		if settingPreview {
			return
		}
		// User typed/edited: prefer entry text from now on.
		fileLoaded = false
		secretBytes = nil
	}

	nEntry := widget.NewEntry()
	nEntry.SetText("5")
	tEntry := widget.NewEntry()
	tEntry.SetText("3")

	chunkEntry := widget.NewEntry()
	chunkEntry.SetText(strconv.Itoa(defaultChunkSize))

	status := widget.NewLabel("")

	loadBtn := widget.NewButton("Load file…", func() {
		dialog.ShowFileOpen(func(rc fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if rc == nil {
				return
			}
			defer rc.Close()

			b, err := io.ReadAll(rc)
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			secretBytes = b
			fileLoaded = true
			settingPreview = true
			secretEntry.SetText(previewBytes(b))
			settingPreview = false
			status.SetText(fmt.Sprintf("Loaded %d bytes from %s", len(b), rc.URI().Name()))
		}, w)
	})

	clearBtn := widget.NewButton("Clear", func() {
		secretBytes = nil
		secretEntry.SetText("")
		status.SetText("")
	})

	generateBtn := widget.NewButton("Generate PDF…", func() {
		// Prefer file bytes if loaded; otherwise use the entry text.
		if !fileLoaded {
			secretBytes = []byte(secretEntry.Text)
		}

		n, err := parseIntInRange(nEntry.Text, 2, 255, "n")
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		t, err := parseIntInRange(tEntry.Text, 2, n, "t")
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		if t > n {
			dialog.ShowError(fmt.Errorf("t must be <= n"), w)
			return
		}
		chunkSize, err := parseIntInRange(chunkEntry.Text, 200, qrpayload.MaxChunkSize, "chunk size")
		if err != nil {
			dialog.ShowError(err, w)
			return
		}
		if len(secretBytes) == 0 {
			dialog.ShowError(fmt.Errorf("secret is empty"), w)
			return
		}

		dialog.ShowFileSave(func(wc fyne.URIWriteCloser, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if wc == nil {
				return
			}
			path := wc.URI().Path()
			_ = wc.Close() // we'll write via gofpdf output file path

			if !strings.HasSuffix(strings.ToLower(path), ".pdf") {
				path += ".pdf"
			}

			docID, err := qrpayload.NewDocID()
			if err != nil {
				dialog.ShowError(err, w)
				return
			}

			x, err := cryptox.GenerateX()
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			salt, err := cryptox.RandomBytes(cryptox.SaltSizeBytes)
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			key, err := cryptox.DeriveAES256Key(x, salt)
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			// Compress before encrypting to reduce QR count.
			compressed, err := cryptox.CompressGzip(secretBytes)
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			env, err := cryptox.EncryptAES256GCM(compressed, key, []byte(docID))
			if err != nil {
				dialog.ShowError(err, w)
				return
			}

			// Shamir split X (32 bytes).
			shares, err := shamir.Split(x, n, t)
			if err != nil {
				dialog.ShowError(err, w)
				return
			}

			chunks, err := qrpayload.SplitBytes(env.Ciphertext, chunkSize)
			if err != nil {
				dialog.ShowError(err, w)
				return
			}

			var cipherItems []pdfgen.Item
			for i, c := range chunks {
				p := qrpayload.CipherChunkV1{
					Common:     qrpayload.Common{V: qrpayload.Version, Type: qrpayload.TypeCipherChunk, Doc: docID},
					KDF:        "HKDF-SHA256",
					AEAD:       "AES-256-GCM",
					Comp:       "gzip",
					N:          n,
					T:          t,
					SaltB64:    qrpayload.B64(salt),
					NonceB64:   qrpayload.B64(env.Nonce),
					ChunkIndex: i + 1,
					ChunkTotal: len(chunks),
					DataB64:    qrpayload.B64(c),
				}
				s, err := qrpayload.MarshalJSON(p)
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				cipherItems = append(cipherItems, pdfgen.Item{
					Title:   fmt.Sprintf("DOC %s CIPHERTEXT %d/%d", docID, i+1, len(chunks)),
					Payload: s,
				})
			}

			var shareItems []pdfgen.Item
			for i, sh := range shares {
				p := qrpayload.ShareV1{
					Common:   qrpayload.Common{V: qrpayload.Version, Type: qrpayload.TypeShare, Doc: docID},
					N:        n,
					T:        t,
					ShareB64: qrpayload.B64(sh),
				}
				s, err := qrpayload.MarshalJSON(p)
				if err != nil {
					dialog.ShowError(err, w)
					return
				}
				shareItems = append(shareItems, pdfgen.Item{
					Title:   fmt.Sprintf("DOC %s // SHARE %d/%d (need %d)", docID, i+1, n, t),
					Payload: s,
				})
			}

			if err := pdfgen.RenderCiphertextThenShares(cipherItems, shareItems, path, pdfgen.DefaultOptions()); err != nil {
				dialog.ShowError(err, w)
				return
			}
			status.SetText(fmt.Sprintf("Wrote %s (%d ciphertext QR(s), %d share page(s))", path, len(chunks), len(shares)))
			dialog.ShowInformation("PDF generated", status.Text, w)
		}, w)
	})

	form := widget.NewForm(
		widget.NewFormItem("Total shares (n)", nEntry),
		widget.NewFormItem("Threshold (t)", tEntry),
		widget.NewFormItem("Cipher chunk size (bytes)", chunkEntry),
	)

	top := container.NewHBox(loadBtn, clearBtn, generateBtn)

	content := container.NewBorder(
		container.NewVBox(top, form, widget.NewSeparator()),
		container.NewVBox(widget.NewSeparator(), status),
		nil,
		nil,
		secretEntry,
	)
	return content, nil
}

func buildDecryptTab(w fyne.Window) (fyne.CanvasObject, error) {
	var inputPaths []string
	var recoveredBytes []byte
	var recoveredDocID string
	status := widget.NewLabel("")

	filesLabel := widget.NewLabel("No files selected.")
	secretOut := widget.NewMultiLineEntry()
	secretOut.SetPlaceHolder("Recovered secret will appear here (or save to file).")
	secretOut.Disable()
	secretOut.Wrapping = fyne.TextWrapWord

	refreshFilesLabel := func() {
		if len(inputPaths) == 0 {
			filesLabel.SetText("No files selected.")
			return
		}
		filesLabel.SetText(fmt.Sprintf("%d file(s): %s", len(inputPaths), strings.Join(shortenPaths(inputPaths), ", ")))
	}

	addBtn := widget.NewButton("Add file…", func() {
		dialog.ShowFileOpen(func(rc fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if rc == nil {
				return
			}
			p := rc.URI().Path()
			_ = rc.Close()
			if err := inputscan.ValidateInputPath(p); err != nil {
				dialog.ShowError(err, w)
				return
			}
			inputPaths = append(inputPaths, p)
			refreshFilesLabel()
			status.SetText("")
		}, w)
	})

	clearBtn := widget.NewButton("Clear", func() {
		inputPaths = nil
		recoveredBytes = nil
		recoveredDocID = ""
		refreshFilesLabel()
		status.SetText("")
		secretOut.SetText("")
	})

	recoverBtn := widget.NewButton("Recover secret", func() {
		if len(inputPaths) == 0 {
			dialog.ShowError(fmt.Errorf("no input files selected"), w)
			return
		}

		var payloads []string
		var scanErrs []string
		for _, p := range inputPaths {
			txts, err := inputscan.ScanFile(p)
			if err != nil {
				// Keep going; user may have mixed files. Report per-file failures below.
				scanErrs = append(scanErrs, fmt.Sprintf("%s: %v", filepath.Base(p), err))
				continue
			}
			payloads = append(payloads, txts...)
		}
		withScanErrs := func(err error) error {
			if len(scanErrs) == 0 {
				return err
			}
			return fmt.Errorf("%w\n\nFile(s) that could not be scanned:\n%s", err, strings.Join(scanErrs, "\n"))
		}
		reportSkipped := func() {
			if len(scanErrs) > 0 {
				dialog.ShowInformation("Some files were skipped", strings.Join(scanErrs, "\n"), w)
			}
		}
		groups, err := recover.ParseAndGroup(payloads)
		if err != nil {
			dialog.ShowError(withScanErrs(err), w)
			return
		}
		summaries := recover.Summaries(groups)
		if len(summaries) == 1 {
			res, err := recover.RecoverSecret(groups[summaries[0].DocID])
			if err != nil {
				dialog.ShowError(withScanErrs(err), w)
				return
			}
			recoveredBytes = res.Secret
			recoveredDocID = res.DocID
			showRecovered(w, secretOut, status, res)
			reportSkipped()
			return
		}

		// Multiple doc IDs found: prompt user.
		var opts []string
		for _, s := range summaries {
			opts = append(opts, fmt.Sprintf("%s (cipher %d/%d, shares %d/%d)", s.DocID, s.CipherChunksHave, s.CipherChunksNeed, s.SharesHave, s.SharesNeed))
		}
		selectWidget := widget.NewSelect(opts, func(_ string) {})
		selectWidget.SetSelected(opts[0])
		d := dialog.NewCustomConfirm("Select document", "Recover", "Cancel", selectWidget, func(ok bool) {
			if !ok {
				return
			}
			choice := selectWidget.Selected
			docID := strings.SplitN(choice, " ", 2)[0]
			res, err := recover.RecoverSecret(groups[docID])
			if err != nil {
				dialog.ShowError(withScanErrs(err), w)
				return
			}
			recoveredBytes = res.Secret
			recoveredDocID = res.DocID
			showRecovered(w, secretOut, status, res)
			reportSkipped()
		}, w)
		d.Show()
	})

	saveBtn := widget.NewButton("Save recovered secret…", func() {
		if len(recoveredBytes) == 0 {
			dialog.ShowError(fmt.Errorf("nothing to save yet"), w)
			return
		}
		dialog.ShowFileSave(func(wc fyne.URIWriteCloser, err error) {
			if err != nil {
				dialog.ShowError(err, w)
				return
			}
			if wc == nil {
				return
			}
			defer wc.Close()
			_, _ = io.Copy(wc, bytes.NewReader(recoveredBytes))
			status.SetText(fmt.Sprintf("Saved DOC %s to %s", recoveredDocID, wc.URI().Name()))
		}, w)
	})

	top := container.NewHBox(addBtn, clearBtn, recoverBtn, saveBtn)
	return container.NewBorder(
		container.NewVBox(top, filesLabel, widget.NewSeparator()),
		container.NewVBox(widget.NewSeparator(), status),
		nil, nil,
		secretOut,
	), nil
}

func parseIntInRange(s string, min, max int, name string) (int, error) {
	v, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("%s must be an integer", name)
	}
	if v < min || v > max {
		return 0, fmt.Errorf("%s must be in [%d, %d]", name, min, max)
	}
	return v, nil
}

func previewBytes(b []byte) string {
	const max = 16_000
	if utf8.Valid(b) {
		s := string(b)
		if len(s) > max {
			return s[:max] + "\n…(truncated preview)…"
		}
		return s
	}
	// For binary input, show a short, safe preview.
	origLen := len(b)
	if len(b) > 256 {
		b = b[:256]
	}
	return fmt.Sprintf("[binary secret: %d bytes]\n(first 256 bytes as base64)\n%s", origLen, qrpayload.B64(b))
}

func showRecovered(w fyne.Window, out *widget.Entry, status *widget.Label, res *recover.RecoveryResult) {
	if utf8.Valid(res.Secret) {
		out.Enable()
		out.SetText(string(res.Secret))
		out.Disable()
		status.SetText(fmt.Sprintf("Recovered DOC %s (%d bytes)", res.DocID, len(res.Secret)))
		return
	}
	// For binary: save to file recommended.
	out.Enable()
	out.SetText(fmt.Sprintf("[binary secret: %d bytes]\nSave to file to preserve exact bytes.", len(res.Secret)))
	out.Disable()
	status.SetText(fmt.Sprintf("Recovered DOC %s (binary, %d bytes)", res.DocID, len(res.Secret)))
	dialog.ShowInformation("Recovered binary secret", "Secret is binary; please use “Save recovered secret…” to export bytes.", w)
}

func shortenPaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, filepath.Base(p))
	}
	return out
}
