package tui

import (
	"os"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"hoot/nip46"
)

// TestQRViewLayout dumps the full View() at every reasonable size and
// captures row-by-row layout information so we can find centering
// problems. The user's complaint is that the QR screen layout is
// "not quite together" — meaning the title, QR, and footer don't
// line up as a unit. We dump raw view output plus structural
// measurements (line count, leftmost column with content) for each
// size.
func TestQRViewLayout(t *testing.T) {
	const fakeURI = "nostrconnect://20366413937be6e239d53dd36a98028404fb20e2af300858ba0e31ab7ba9a97c?relay=wss%3A%2F%2Frelay.damus.io&metadata=%7B%22name%22%3A%22hoot%22%7D"

	cases := []struct{ w, h int }{
		{40, 20}, {60, 20}, {80, 24}, {100, 30}, {120, 40}, {160, 50},
	}

	for _, c := range cases {
		m := NewModel()
		m.SetCallbacks(
			func() bool { return false },
			func(string) (string, string, error) { return "", "", nil },
			func() error { return nil },
			func(string, string, bool) (string, error) { return "", nil },
			func(string) error { return nil },
			func() ([]FeedPost, error) { return nil, nil },
			func() (string, error) { return fakeURI, nil },
					func() (string, *nip46.ProfileMetadata, error) { return "", nil, nil },
			func() ([]string, error) { return nil, nil },
			func([]string) error { return nil },
		)
		m.screen = ScreenQRLogin
		upd, _ := m.Update(tea.WindowSizeMsg{Width: c.w, Height: c.h})
		m = upd.(Model)
		upd, _ = m.Update(qrGeneratedMsg{uri: fakeURI})
		m = upd.(Model)
		// Pump enough generic updates so any pending regen/decode runs.
		for i := 0; i < 5; i++ {
			upd, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{}})
			m = upd.(Model)
		}

		view := m.View()
		rawPath := "/tmp/hoot-qr-layout-" + itoa(c.w) + "x" + itoa(c.h) + ".txt"
		_ = os.WriteFile(rawPath, []byte(view), 0644)
		t.Logf("=== w=%d h=%d raw view dumped to %s ===", c.w, c.h, rawPath)

		// Quick header analysis: where is "Scan with Amber"? Where is
		// the QR (first | or ▀ block)? Where is "Waiting for
		// connection..."?  Where is "Press Esc"?
		lines := strings.Split(view, "\n")
		var headerLine, firstQRLine, footerScanLine, footerEscLine int = -1, -1, -1, -1
		for i, l := range lines {
			switch {
			case strings.Contains(l, "Scan with Amber") && headerLine == -1:
				headerLine = i
			case (strings.Contains(l, "▄") || strings.Contains(l, "█")) && firstQRLine == -1:
				firstQRLine = i
			case strings.Contains(l, "Waiting for connection") && footerScanLine == -1:
				footerScanLine = i
			case strings.Contains(l, "Press Esc") && footerEscLine == -1:
				footerEscLine = i
			}
		}
		t.Logf("  header at line %d, first QR line %d, footer/Waiting line %d, footer/Press line %d, total %d lines",
			headerLine, firstQRLine, footerScanLine, footerEscLine, len(lines))

		// Compute leftmost content column for each of those lines,
		// measuring by runewidth.StringWidth would be ideal but the
		// simpler "first non-space column" is enough to detect misalignment.
		for label, n := range map[string]int{"header": headerLine, "firstQR": firstQRLine, "waiting": footerScanLine, "esc": footerEscLine} {
			if n < 0 || n >= len(lines) {
				continue
			}
			l := lines[n]
			indent := 0
			for _, r := range l {
				if r == ' ' {
					indent++
				} else {
					break
				}
			}
			t.Logf("  %-8s line %d indent=%d (visible col %d)", label, n, indent, indent)
		}
	}
}

// itoa is here so this test file doesn't pull in strconv just for sizes.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	digits := []byte{}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if neg {
		digits = append([]byte{'-'}, digits...)
	}
	return string(digits)
}
