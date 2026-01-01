package appui

import (
	"strings"
	"testing"

	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	recoverpkg "github.com/wildy/ssssecret/internal/recover"
)

func TestParseIntInRange(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		got, err := parseIntInRange("7", 5, 10, "n")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 7 {
			t.Fatalf("expected 7, got %d", got)
		}
	})

	t.Run("non_integer", func(t *testing.T) {
		if _, err := parseIntInRange("abc", 1, 3, "n"); err == nil {
			t.Fatal("expected error for non-integer input")
		}
	})

	t.Run("out_of_range", func(t *testing.T) {
		if _, err := parseIntInRange("0", 1, 3, "n"); err == nil {
			t.Fatal("expected error for value below range")
		}
		if _, err := parseIntInRange("5", 1, 3, "n"); err == nil {
			t.Fatal("expected error for value above range")
		}
	})
}

func TestPreviewBytes(t *testing.T) {
	t.Run("utf8_passthrough", func(t *testing.T) {
		const msg = "hello secret"
		if got := previewBytes([]byte(msg)); got != msg {
			t.Fatalf("expected %q, got %q", msg, got)
		}
	})

	t.Run("binary_summary", func(t *testing.T) {
		got := previewBytes([]byte{0xFF, 0x00, 0x01})
		if !strings.Contains(got, "[binary secret: 3 bytes]") {
			t.Fatalf("missing binary header in %q", got)
		}
		if !strings.Contains(got, "/wAB") {
			t.Fatalf("missing base64 preview in %q", got)
		}
	})

	t.Run("truncate_long_utf8", func(t *testing.T) {
		long := strings.Repeat("a", 16_010)
		got := previewBytes([]byte(long))
		if !strings.HasSuffix(got, "\n…(truncated preview)…") {
			t.Fatalf("expected truncated suffix, got %q", got[len(got)-30:])
		}
		if len(got) != 16_000+len("\n…(truncated preview)…") {
			t.Fatalf("unexpected length after truncation: %d", len(got))
		}
	})
}

func TestShortenPaths(t *testing.T) {
	paths := []string{"/tmp/foo/bar.txt", "baz/qux"}
	got := shortenPaths(paths)
	want := []string{"bar.txt", "qux"}
	if len(got) != len(want) {
		t.Fatalf("expected %d paths, got %d", len(want), len(got))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("index %d: expected %q, got %q", i, want[i], got[i])
		}
	}
}

func TestShowRecovered(t *testing.T) {
	app := test.NewApp()
	t.Cleanup(app.Quit)

	t.Run("utf8_secret", func(t *testing.T) {
		w := test.NewWindow(nil)
		defer w.Close()

		out := widget.NewEntry()
		status := widget.NewLabel("")
		res := &recoverpkg.RecoveryResult{DocID: "doc-text", Secret: []byte("hello")}

		showRecovered(w, out, status, res)

		if out.Text != "hello" {
			t.Fatalf("expected entry text %q, got %q", "hello", out.Text)
		}
		if !out.Disabled() {
			t.Fatal("entry should be disabled after display")
		}
		if got := status.Text; !strings.Contains(got, "Recovered DOC doc-text") {
			t.Fatalf("unexpected status text: %q", got)
		}
	})

	t.Run("binary_secret", func(t *testing.T) {
		w := test.NewWindow(nil)
		defer w.Close()

		out := widget.NewEntry()
		status := widget.NewLabel("")
		res := &recoverpkg.RecoveryResult{DocID: "doc-bin", Secret: []byte{0x00, 0xFF, 0xAA}}

		showRecovered(w, out, status, res)

		if !strings.Contains(out.Text, "[binary secret: 3 bytes]") {
			t.Fatalf("unexpected entry text: %q", out.Text)
		}
		if !out.Disabled() {
			t.Fatal("entry should be disabled after display")
		}
		if got := status.Text; got != "Recovered DOC doc-bin (binary, 3 bytes)" {
			t.Fatalf("unexpected status text: %q", got)
		}
	})
}
