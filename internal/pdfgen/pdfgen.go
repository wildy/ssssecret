package pdfgen

import (
	"bytes"
	"fmt"

	"github.com/jung-kurt/gofpdf"
	"github.com/skip2/go-qrcode"
)

type Item struct {
	Title   string
	Payload string // JSON text encoded in QR
}

type Options struct {
	PageWMM        float64
	PageHMM        float64
	MarginMM       float64
	GridCols       int
	GridRows       int
	QRPixelSize    int
	ErrorLevel     qrcode.RecoveryLevel
	TitleFontSize  float64
	FooterFontSize float64
}

func DefaultOptions() Options {
	return Options{
		PageWMM:        210,
		PageHMM:        297,
		MarginMM:       10,
		GridCols:       2,
		GridRows:       3,
		QRPixelSize:    640,
		ErrorLevel:     qrcode.Medium,
		TitleFontSize:  12,
		FooterFontSize: 9,
	}
}

// RenderPDF renders all items in a grid (legacy behavior).
func RenderPDF(items []Item, outPath string, opts Options) error {
	return RenderCiphertextThenShares(items, nil, outPath, opts)
}

// RenderCiphertextThenShares renders ciphertext items continuously in a grid (spanning pages as needed),
// then renders each share item on its own page.
func RenderCiphertextThenShares(cipherItems []Item, shareItems []Item, outPath string, opts Options) error {
	if opts.GridCols <= 0 || opts.GridRows <= 0 {
		return fmt.Errorf("invalid grid %dx%d", opts.GridCols, opts.GridRows)
	}
	pdf := gofpdf.NewCustom(&gofpdf.InitType{
		UnitStr: "mm",
		Size:    gofpdf.SizeType{Wd: opts.PageWMM, Ht: opts.PageHMM},
	})
	pdf.SetMargins(opts.MarginMM, opts.MarginMM, opts.MarginMM)
	pdf.SetAutoPageBreak(true, opts.MarginMM)
	pdf.SetFont("Helvetica", "", opts.TitleFontSize)

	if err := renderGrid(pdf, cipherItems, opts); err != nil {
		return err
	}
	if err := renderOnePerPage(pdf, shareItems, opts); err != nil {
		return err
	}

	return pdf.OutputFileAndClose(outPath)
}

func renderGrid(pdf *gofpdf.Fpdf, items []Item, opts Options) error {
	if len(items) == 0 {
		return nil
	}
	pageW, pageH := opts.PageWMM, opts.PageHMM
	usableW := pageW - 2*opts.MarginMM
	usableH := pageH - 2*opts.MarginMM

	cellW := usableW / float64(opts.GridCols)
	cellH := usableH / float64(opts.GridRows)
	qrMM := min(cellW, cellH) * 0.78 // leave room for text labels
	if qrMM < 30 {
		return fmt.Errorf("QR too small (%.1fmm). Reduce grid density", qrMM)
	}

	pdf.AddPage()

	perPage := opts.GridCols * opts.GridRows
	for i, it := range items {
		if i > 0 && i%perPage == 0 {
			pdf.AddPage()
		}
		slot := i % perPage
		col := slot % opts.GridCols
		row := slot / opts.GridCols

		x0 := opts.MarginMM + float64(col)*cellW
		y0 := opts.MarginMM + float64(row)*cellH

		qr, err := qrcode.New(it.Payload, opts.ErrorLevel)
		if err != nil {
			return err
		}
		pngBytes, err := qr.PNG(opts.QRPixelSize)
		if err != nil {
			return err
		}

		imgName := fmt.Sprintf("qr-grid-%d", i)
		opt := gofpdf.ImageOptions{ImageType: "PNG", ReadDpi: true}
		pdf.RegisterImageOptionsReader(imgName, opt, bytes.NewReader(pngBytes))

		// Title
		pdf.SetXY(x0, y0)
		pdf.SetFont("Helvetica", "B", opts.TitleFontSize)
		pdf.MultiCell(cellW, 6, it.Title, "", "L", false)

		// QR image
		qrX := x0 + (cellW-qrMM)/2
		qrY := y0 + 10
		pdf.ImageOptions(imgName, qrX, qrY, qrMM, qrMM, false, opt, 0, "")

		// Footer hint
		pdf.SetFont("Helvetica", "", opts.FooterFontSize)
		pdf.SetXY(x0, qrY+qrMM+2)
		pdf.MultiCell(cellW, 4.5, "Scan & store securely. Keep printed copies offline.", "", "L", false)
	}
	return nil
}

func renderOnePerPage(pdf *gofpdf.Fpdf, items []Item, opts Options) error {
	if len(items) == 0 {
		return nil
	}
	pageW, pageH := opts.PageWMM, opts.PageHMM
	usableW := pageW - 2*opts.MarginMM
	usableH := pageH - 2*opts.MarginMM

	// Larger QR per page for shares.
	qrMM := min(usableW, usableH) * 0.80
	if qrMM < 60 {
		return fmt.Errorf("QR too small for one-per-page layout (%.1fmm)", qrMM)
	}

	for i, it := range items {
		pdf.AddPage()

		qr, err := qrcode.New(it.Payload, opts.ErrorLevel)
		if err != nil {
			return err
		}
		pngBytes, err := qr.PNG(opts.QRPixelSize)
		if err != nil {
			return err
		}

		imgName := fmt.Sprintf("qr-share-%d", i)
		opt := gofpdf.ImageOptions{ImageType: "PNG", ReadDpi: true}
		pdf.RegisterImageOptionsReader(imgName, opt, bytes.NewReader(pngBytes))

		pdf.SetFont("Helvetica", "B", opts.TitleFontSize+2)
		pdf.SetXY(opts.MarginMM, opts.MarginMM)
		pdf.MultiCell(usableW, 7, it.Title, "", "L", false)

		qrX := opts.MarginMM + (usableW-qrMM)/2
		qrY := opts.MarginMM + 18
		pdf.ImageOptions(imgName, qrX, qrY, qrMM, qrMM, false, opt, 0, "")

		pdf.SetFont("Helvetica", "", opts.FooterFontSize)
		pdf.SetXY(opts.MarginMM, qrY+qrMM+3)
		pdf.MultiCell(usableW, 4.5, "This page is a Shamir share. Keep shares separate. Do not photograph or upload.", "", "L", false)
	}
	return nil
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
