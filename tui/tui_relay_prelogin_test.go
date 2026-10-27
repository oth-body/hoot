package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"hoot/nip46"
)

// TestConfigureRelaysBeforeLogin verifies that the login menu offers a
// "Configure relays" entry, that selecting it opens the relay screen with
// the persisted relay list preloaded, that adding/removing a relay calls
// through to the save callback, and that Esc returns to the login screen
// (not Home, since no session exists yet).
func TestConfigureRelaysBeforeLogin(t *testing.T) {
	savedRelays := []string{"wss://relay.damus.io"}
	var lastSaved []string

	m := NewModel()
	m.SetCallbacks(
		func() bool { return false },
		func(string) (string, string, error) { return "", "", nil },
		func() error { return nil },
		func(string, string, bool) (string, error) { return "", nil },
		func(string) error { return nil },
		func() ([]FeedPost, error) { return nil, nil },
		func() (string, error) { return "", nil },
		func() (string, *nip46.ProfileMetadata, error) { return "", nil, nil },
		func() ([]string, error) { return savedRelays, nil },
		func(relays []string) error { lastSaved = relays; return nil },
	)

	// No profiles yet: menu is [Create new profile, Scan QR, Configure relays].
	if m.loggedIn {
		t.Fatalf("expected fresh model to not be logged in")
	}
	view := m.View()
	if !strings.Contains(view, "Configure relays") {
		t.Fatalf("login screen missing 'Configure relays' option:\n%s", view)
	}

	// Move cursor down twice to land on "Configure relays" (index 2).
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updated.(Model)
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyDown})
	m = updated.(Model)
	if m.cursor != 2 {
		t.Fatalf("expected cursor at 2 after two down-presses, got %d", m.cursor)
	}

	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if m.screen != ScreenRelays {
		t.Fatalf("expected ScreenRelays after selecting Configure relays, got %v", m.screen)
	}
	if len(m.relays) != 1 || m.relays[0] != "wss://relay.damus.io" {
		t.Fatalf("expected preloaded relay list, got %v", m.relays)
	}

	// Add a relay.
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	m = updated.(Model)
	if !m.addingRelay {
		t.Fatalf("expected addingRelay=true after pressing 'a'")
	}
	for _, r := range "nos.lol" {
		updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = updated.(Model)
	}
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = updated.(Model)
	if len(m.relays) != 2 || m.relays[1] != "wss://nos.lol" {
		t.Fatalf("expected relay to be added with wss:// prefix, got %v", m.relays)
	}
	if len(lastSaved) != 2 {
		t.Fatalf("expected onSaveRelays to be called with 2 relays, got %v", lastSaved)
	}

	// Delete the selected (first) relay.
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	m = updated.(Model)
	if len(m.relays) != 1 || m.relays[0] != "wss://nos.lol" {
		t.Fatalf("expected first relay removed, got %v", m.relays)
	}

	// Esc should return to the login screen, not Home, since no one is logged in.
	updated, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = updated.(Model)
	if m.screen != ScreenLogin {
		t.Fatalf("expected Esc to return to ScreenLogin pre-login, got %v", m.screen)
	}
}
