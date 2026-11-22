package tui

import (
	"errors"
	"strings"
	"testing"
	"time"

	"hoot/nip46"

	tea "github.com/charmbracelet/bubbletea"
)

// qrFailure is the kind of actionable error nip46.ConnectRelays returns
// (proxy env var set, all relays unreachable, bad relays.txt, ...).
var qrFailure = errors.New("refusing to dial relays through HTTPS_PROXY=socks5h://127.0.0.1:9050: NIP-46 sign-in requires a direct connection to the relay")

func newQRModel(onInitQR func() (string, error)) Model {
	m := NewModel()
	m.SetCallbacks(
		func() bool { return false },
		func(string) (string, string, error) { return "", "", nil },
		func() error { return nil },
		func(string, string, bool) (string, error) { return "", nil },
		func(string) error { return nil },
		func() ([]FeedPost, error) { return nil, nil },
		onInitQR,
		func() (string, *nip46.ProfileMetadata, error) { return "", nil, nil },
		func() ([]string, error) { return nil, nil },
		func([]string) error { return nil },
	)
	return m
}

// TestQRErrorRendersOnQRScreen is the regression test for the reported UX:
// a pairing failure used to be appended after the QR block and footer (or
// only became visible after Esc, on the main menu). It must be rendered on
// the QR screen itself, replacing the stale QR and "Waiting..." hint.
func TestQRErrorRendersOnQRScreen(t *testing.T) {
	m := newQRModel(func() (string, error) { return "", qrFailure })

	upd, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = upd.(Model)

	m.cursor = 1 // Scan QR with Amber
	upd, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = upd.(Model)
	if cmd == nil {
		t.Fatal("expected initQR cmd after selecting Scan QR")
	}

	msg := cmd()
	if _, ok := msg.(qrInitErrorMsg); !ok {
		t.Fatalf("expected qrInitErrorMsg, got %T: %v", msg, msg)
	}
	upd, _ = m.Update(msg)
	m = upd.(Model)

	if m.screen != ScreenQRLogin {
		t.Fatalf("error should keep the user on the QR screen, got %v", m.screen)
	}
	if m.qrError == "" {
		t.Fatal("qrError was not set")
	}

	view := m.View()
	if !strings.Contains(view, "Sign-in failed") {
		t.Fatalf("error missing from QR view:\n%s", view)
	}
	if strings.Contains(view, "Waiting for connection") {
		t.Fatalf("stale 'Waiting for connection' hint still shown after failure:\n%s", view)
	}
	if got := strings.Count(view, "Sign-in failed"); got != 1 {
		t.Fatalf("error rendered %d times (want once, inside the QR block):\n%s", got, view)
	}
	errAt := strings.Index(view, "Sign-in failed")
	footerAt := strings.Index(view, "Press Esc")
	if errAt < 0 || footerAt < 0 || errAt > footerAt {
		t.Fatalf("error should be inside the QR block, above the footer:\n%s", view)
	}
}

// TestQRErrorClearedOnRetry makes sure a subsequent successful QR init
// removes the error state rather than showing both the QR and the failure.
func TestQRErrorClearedOnRetry(t *testing.T) {
	m := newQRModel(func() (string, error) { return "", qrFailure })
	upd, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = upd.(Model)
	upd, _ = m.Update(qrInitErrorMsg{err: qrFailure})
	m = upd.(Model)

	const uri = "nostrconnect://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef?relay=wss%3A%2F%2Frelay.damus.io"
	upd, _ = m.Update(qrGeneratedMsg{uri: uri})
	m = upd.(Model)
	upd, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{}})
	m = upd.(Model)

	if m.qrError != "" {
		t.Fatalf("qrError not cleared on retry: %q", m.qrError)
	}
	view := m.View()
	if strings.Contains(view, "Sign-in failed") {
		t.Fatalf("stale error still rendered after retry:\n%s", view)
	}
	if m.qrRendered == "" {
		t.Fatal("QR not rendered after retry")
	}
}

// TestQRLongWaitHintEscalates pins the UX fix: the generic "Waiting for
// connection..." line must switch to an actionable hint once the user has
// been staring at the QR for a while, so a locked/closed Amber doesn't
// leave them stuck forever.
func TestQRLongWaitHintEscalates(t *testing.T) {
	m := newQRModel(func() (string, error) {
		return "nostrconnect://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef?relay=wss%3A%2F%2Frelay.damus.io", nil
	})
	upd, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = upd.(Model)
	m.screen = ScreenQRLogin
	upd, _ = m.Update(qrGeneratedMsg{uri: "nostrconnect://0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef?relay=wss%3A%2F%2Frelay.damus.io"})
	m = upd.(Model)
	m.regenerateQR()

	if got := m.View(); !strings.Contains(got, "Waiting for connection") {
		t.Fatalf("fresh QR should show the normal waiting hint:\n%s", got)
	}

	m.qrWaitStart = time.Now().Add(-longQRWait - time.Second)
	got := m.View()
	if strings.Contains(got, "Waiting for connection") {
		t.Fatalf("long wait still shows the generic hint:\n%s", got)
	}
	if !strings.Contains(got, "Still waiting") {
		t.Fatalf("long wait did not show the actionable hint:\n%s", got)
	}
}

// TestLateQRErrorStillShowsOnLoginMenu keeps the old fallback: if the async
// error lands after the user already left the QR screen, it should still be
// visible on the login menu rather than being swallowed.
func TestLateQRErrorStillShowsOnLoginMenu(t *testing.T) {
	m := newQRModel(func() (string, error) { return "", qrFailure })
	upd, _ := m.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
	m = upd.(Model)
	m.screen = ScreenQRLogin

	upd, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = upd.(Model)
	if m.screen != ScreenLogin {
		t.Fatalf("esc should return to login menu, got %v", m.screen)
	}

	upd, _ = m.Update(qrInitErrorMsg{err: qrFailure})
	m = upd.(Model)
	if !strings.Contains(m.View(), "Sign-in failed") {
		t.Fatalf("late error not shown on login menu:\n%s", m.View())
	}
}
