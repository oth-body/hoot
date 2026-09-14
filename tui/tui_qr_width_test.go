package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mattn/go-runewidth"
)

// TestQRVisualFitsTerminalWidth verifies the rendered QR code's visual
// width fits in a typical terminal width (≥ 80 cols). The previous bug
// passed qrterminal.BLACK/WHITE as block characters; those are 6-byte
// ANSI escape sequences, and using them as the half-block character
// produced ~335 visual columns for a typical nostrconnect:// URI,
// which lipgloss wrapped into ~80 wrapped lines of unreadable bars.
func TestQRVisualFitsTerminalWidth(t *testing.T) {
	const fakeURI = "nostrconnect://20366413937be6e239d53dd36a98028404fb20e2af300858ba0e31ab7ba9a97c?relay=wss%3A%2F%2Frelay.damus.io&metadata=%7B%22name%22%3A%22hoot%22%7D"

	m := NewModel()
	m.SetCallbacks(
		func() bool { return false },
		func(string) (string, string, error) { return "", "", nil },
		func() error { return nil },
		func(string, string, bool) (string, error) { return "", nil },
		func(string) error { return nil },
		func() ([]FeedPost, error) { return nil, nil },
		func() (string, error) { return fakeURI, nil },
		func() (string, error) { return "", nil },
		func() ([]string, error) { return nil, nil },
		func([]string) error { return nil },
	)

	type tc struct {
		w, h int
	}
	cases := []tc{{40, 20}, {50, 24}, {60, 24}, {80, 24}, {100, 30}, {120, 40}, {160, 50}}

	for _, c := range cases {
		// Reset QR state for a clean run
		m.qrData = ""
		m.qrRendered = ""
		m.qrNeedsRegeneration = false
		m.qrReady = false
		m.width = 0
		m.height = 0
		m.screen = ScreenQRLogin

		upd, _ := m.Update(tea.WindowSizeMsg{Width: c.w, Height: c.h})
		m = upd.(Model)
		upd, _ = m.Update(qrGeneratedMsg{uri: fakeURI})
		m = upd.(Model)
		// drain
		for i := 0; i < 3; i++ {
			upd, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{}})
			m = upd.(Model)
		}

		if m.qrRendered == "" {
			t.Errorf("w=%d h=%d: qrRendered empty", c.w, c.h)
			continue
		}

		// Find the visual max width of the qrRendered text using
		// runewidth so we count columns, not bytes.
		var maxVisual int
		for _, l := range strings.Split(m.qrRendered, "\n") {
			if w := runewidth.StringWidth(l); w > maxVisual {
				maxVisual = w
			}
		}

		// QR must fit in 80 columns — that's the lowest "normal" width.
		// We do allow narrower terminals to fail here because the
		// nostrconnect URI is a real-world minimum size.
		if c.w >= 80 && maxVisual > c.w {
			t.Errorf("w=%d h=%d: QR visual width %d > terminal width %d — QR will be wrapped/truncated",
				c.w, c.h, maxVisual, c.w)
		}
		t.Logf("w=%d h=%d: qrRendered max visual width = %d cols", c.w, c.h, maxVisual)

		// For an 80x24 terminal (the canonical case), print what the
		// user actually sees so a human can confirm the QR renders.
		if c.w == 80 && c.h == 24 {
			view := m.View()
			t.Logf("\n----- View() at 80x24 -----\n%s\n----- end View() -----", view)
		}
	}
}
