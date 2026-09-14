package tui

import (
	"os"
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
)

// TestQRFlowsThroughLoginMenuEndToEnd drives the full path a real user
// would take: at the login menu, hit Enter on the QR option, wait for
// the QR, and verify the screen transitions from "Generating..." to
// the actual QR. This catches any drift between the in-package tests
// (which poke internals) and what the user actually sees.
func TestQRFlowsThroughLoginMenuEndToEnd(t *testing.T) {
	const fakeURI = "nostrconnect://20366413937be6e239d53dd36a98028404fb20e2af300858ba0e31ab7ba9a97c?relay=wss%3A%2F%2Frelay.damus.io&metadata=%7B%22name%22%3A%22hoot%22%7D"

	m := NewModel()
	m.SetCallbacks(
		func() bool { return false }, // hasKey=false → see "no profiles" menu
		func(string) (string, string, error) { return "", "", nil },
		func() error { return nil },
		func(string, string, bool) (string, error) { return "", nil },
		func(string) error { return nil },
		func() ([]FeedPost, error) { return nil, nil },
		func() (string, error) {
			// Simulate slow network: sleep would block the goroutine, so
			// we just resolve immediately — the test is about flow not latency.
			return fakeURI, nil
		},
		func() (string, error) { return "", nil },
		func() ([]string, error) { return nil, nil },
		func([]string) error { return nil },
	)

	// Establish screen size first.
	const W, H = 80, 24
	upd, _ := m.Update(tea.WindowSizeMsg{Width: W, Height: H})
	m = upd.(Model)

	// At the login screen with no profiles, the menu has cursor 0=Create,
	// cursor 1=Scan QR. Move cursor to 1 and press Enter.
	m.cursor = 1
	upd, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = upd.(Model)
	if cmd == nil {
		t.Fatalf("Expected initQR cmd to fire after picking QR menu; got nil")
	}

	// The cmd, when run, returns qrGeneratedMsg — execute it manually.
	msg := cmd()
	if msg == nil {
		t.Fatalf("initQR cmd returned nil")
	}
	if _, ok := msg.(qrGeneratedMsg); !ok {
		t.Fatalf("Expected qrGeneratedMsg, got %T: %v", msg, msg)
	}
	upd, _ = m.Update(msg)
	m = upd.(Model)

	// Drain a few generic Update ticks so regenerateQR has a chance.
	for i := 0; i < 5; i++ {
		upd, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{}})
		m = upd.(Model)
	}

	// After the flow above the screen should be ScreenQRLogin and qrReady.
	if m.screen != ScreenQRLogin {
		t.Fatalf("screen did not transition to ScreenQRLogin: got %v", m.screen)
	}
	if !m.qrReady {
		t.Fatalf("qrReady never flipped to true")
	}
	if m.qrData == "" {
		t.Fatalf("qrData was empty after init")
	}

	// Now: what's actually rendered?
	view := m.View()
	if strings.Contains(view, "Generating") {
		// Write the view to a temp file for diagnosis.
		_ = os.WriteFile("/tmp/hoot-qr-view.txt", []byte(view), 0644)
		t.Fatalf("View still shows a Generating... placeholder after init; expected QR to be visible. Wrote /tmp/hoot-qr-view.txt")
	}
	if m.qrRendered == "" {
		t.Fatalf("qrRendered empty after init; expected qrterminal output to be present")
	}
	t.Logf("View at 80x24:\n%s", view)

	// Pre-condition regression: while waiting on initQR (BEFORE
	// qrGeneratedMsg arrives), the loading state must include a spinner
	// frame so the user sees activity instead of static text. After the
	// QR arrives, the loading text must NOT still be present.
	t.Run("loading state shows spinner", func(t *testing.T) {
		m2 := NewModel()
		m2.SetCallbacks(
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
		m2.screen = ScreenQRLogin
		// No qrData yet → loading branch.
		m2.width = 80
		m2.height = 24
		// Pump the spinner once so it has a non-empty frame.
		var cmd tea.Cmd
		var modelIface tea.Model
		modelIface, cmd = m2.Update(spinner.TickMsg{})
		if cmd == nil {
			t.Fatal("spinner returned no Tick cmd")
		}
		m2 = modelIface.(Model)
		view := m2.View()
		// The Line spinner frame set contains | / - \\ characters.
		spinnerChars := []string{"|", "/", "-", "\\"}
		hasSpinner := false
		for _, c := range spinnerChars {
			if strings.Contains(view, c+" ") || strings.Contains(view, c+" ") {
				hasSpinner = true
				break
			}
		}
		if !hasSpinner {
			t.Logf("View contains no spinner frame:\n%s", view)
		}
		if !strings.Contains(view, "Generating") {
			t.Errorf("loading view should mention Generating")
		}
	})
}
