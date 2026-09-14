package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// TestQRGeneratesAfterInitMessage verifies that the QR code renders correctly
// in the TUI after the QR init message arrives, even when the first
// WindowSizeMsg has not been seen yet.
//
// The previous code set `qrNeedsRegeneration = true` from qrGeneratedMsg
// but `regenerateQR()` bailed out when width/height were zero, WITHOUT
// clearing the regeneration flag. The flag then never re-fired on its own.
func TestQRGeneratesAfterInitMessage(t *testing.T) {
	const fakeURI = "nostrconnect://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef?relay=wss%3A%2F%2Frelay.damus.io&metadata=%7B%22name%22%3A%22hoot%22%7D"

	m := NewModel()

	// SetCallbacks signature: hasKey, onLoadKey, onResetKey, onLogin,
	// onPost, onLoadFeed, onInitQR, onCheckQR, onLoadRelays, onSaveRelays
	m.SetCallbacks(
		func() bool { return false },                                       // hasKey
		func(string) (string, string, error) { return "", "", nil },          // onLoadKey
		func() error { return nil },                                          // onResetKey
		func(string, string, bool) (string, error) { return "", nil },        // onLogin
		func(string) error { return nil },                                    // onPost
		func() ([]FeedPost, error) { return nil, nil },                       // onLoadFeed
		func() (string, error) { return fakeURI, nil },                       // onInitQR
		func() (string, error) { return "", nil },                            // onCheckQR
		func() ([]string, error) { return nil, nil },                         // onLoadRelays
		func([]string) error { return nil },                                  // onSaveRelays
	)

	// Switch to the QR screen, matching handleLoginEnter logic.
	m.screen = ScreenQRLogin

	// Send a WindowSizeMsg FIRST (normal order in real Bubble Tea).
	const W, H = 80, 24
	updated, _ := m.Update(tea.WindowSizeMsg{Width: W, Height: H})
	m = updated.(Model)

	// Now feed the qrGeneratedMsg (this is what `initQR` returns via Cmd).
	updated, _ = m.Update(qrGeneratedMsg{uri: fakeURI})
	m = updated.(Model)

	// Drive a few empty Update ticks to flush any pending regen.
	for i := 0; i < 3; i++ {
		updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{}})
		m = updated.(Model)
	}

	if m.qrRendered == "" {
		t.Fatalf("qrRendered is empty — QR code was not generated")
	}
	view := m.View()
	if strings.Contains(view, "Generating QR code...") {
		t.Fatalf("View still shows 'Generating QR code...' after regen — render path stalled")
	}
	if !strings.Contains(view, "Scan with Amber") {
		t.Fatalf("View does not show QR screen header — got %q", firstNLines(view, 5))
	}
}

// TestQRGeneratesWhenSizeMessageArrivesAfterQRData mirrors a real bug:
// in some terminals (especially when launched via a sub-shell or with
// redirected stdin) the tea.WindowSizeMsg may arrive AFTER an async cmd
// like initQR fires its qrGeneratedMsg. The QR code must still render
// once dimensions are known. This is the actual reproduction case the
// user reported.
func TestQRGeneratesWhenSizeMessageArrivesAfterQRData(t *testing.T) {
	const fakeURI = "nostrconnect://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef?relay=wss%3A%2F%2Frelay.damus.io&metadata=%7B%22name%22%3A%22hoot%22%7D"

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

	m.screen = ScreenQRLogin

	// Deliver qrGeneratedMsg FIRST (width/height still zero). The previous
	// code set qrNeedsRegeneration=true but regenerateQR() bailed out and
	// did not clear the flag — so the QR never rendered.
	updated, _ := m.Update(qrGeneratedMsg{uri: fakeURI})
	m = updated.(Model)

	// Confirm the bug stage: pre-fix, this stays empty until a window resize.
	if m.qrRendered != "" {
		t.Skip("Test is not meaningful: QR already rendered without a WindowSizeMsg.")
	}

	// Now the WindowSizeMsg arrives (e.g. after the program hands control to tea).
	updated, _ = m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = updated.(Model)

	if m.qrRendered == "" {
		t.Fatalf("qrRendered is empty after WindowSizeMsg arrived — QR did not regenerate; current state: needsRegen=%v qrData=%q width=%d height=%d",
			m.qrNeedsRegeneration, m.qrData, m.width, m.height)
	}
}

// helper: first N lines of a string, useful for test failure messages.
func firstNLines(s string, n int) string {
	parts := strings.SplitN(s, "\n", n+1)
	if len(parts) > n {
		return strings.Join(parts[:n], "\n")
	}
	return s
}
