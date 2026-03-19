package tui

import (
	"testing"
)

func TestNewModel(t *testing.T) {
	model := NewModel()

	if model.screen != ScreenLogin {
		t.Errorf("Expected initial screen to be ScreenLogin, got %d", model.screen)
	}

	if model.textInput.Focused() != true {
		t.Error("TextInput should be focused initially")
	}

	if model.textInput.CharLimit != 256 {
		t.Errorf("Expected CharLimit 256, got %d", model.textInput.CharLimit)
	}
}

func TestScreenConstants(t *testing.T) {
	// Verify screen constants are distinct
	screens := map[string]Screen{
		"Login":    ScreenLogin,
		"QRLogin":  ScreenQRLogin,
		"Home":     ScreenHome,
		"Post":     ScreenPost,
		"Feed":     ScreenFeed,
		"DMs":      ScreenDMs,
		"Replies":  ScreenReplies,
		"Tip":      ScreenTip,
		"Relays":   ScreenRelays,
		"Profiles": ScreenProfiles,
	}

	seen := make(map[Screen]bool)
	for name, screen := range screens {
		if seen[screen] {
			t.Errorf("Duplicate screen value: %s has value %d", name, screen)
		}
		seen[screen] = true
	}

	// Verify we have all expected screens
	if len(screens) != 10 {
		t.Errorf("Expected 10 screen types, got %d", len(screens))
	}
}

func TestFeedPost(t *testing.T) {
	post := FeedPost{
		Author:    "npub1test",
		Content:   "Hello world",
		CreatedAt: "2h ago",
	}

	if post.Author != "npub1test" {
		t.Errorf("Author mismatch: %s", post.Author)
	}
	if post.Content != "Hello world" {
		t.Errorf("Content mismatch: %s", post.Content)
	}
	if post.CreatedAt != "2h ago" {
		t.Errorf("CreatedAt mismatch: %s", post.CreatedAt)
	}
}

func TestProfileInfo(t *testing.T) {
	profile := ProfileInfo{
		ID:        "profile-123",
		Name:      "Test User",
		PublicKey: "npub1abc123",
	}

	if profile.ID != "profile-123" {
		t.Errorf("ID mismatch: %s", profile.ID)
	}
	if profile.Name != "Test User" {
		t.Errorf("Name mismatch: %s", profile.Name)
	}
	if profile.PublicKey != "npub1abc123" {
		t.Errorf("PublicKey mismatch: %s", profile.PublicKey)
	}
}

func TestStyles(t *testing.T) {
	// Verify styles are defined
	if titleStyle.GetMarginBottom() != 1 {
		t.Error("titleStyle should have margin bottom")
	}

	// These should not panic
	_ = menuStyle.Render("test")
	_ = selectedStyle.Render("test")
	_ = inputStyle.Render("test")
	_ = errorStyle.Render("test")
	_ = successStyle.Render("test")
}

func TestModelInitialValues(t *testing.T) {
	model := NewModel()

	// Check initial state
	if model.loggedIn {
		t.Error("Model should not be logged in initially")
	}

	if model.publicKey != "" {
		t.Error("PublicKey should be empty initially")
	}

	if model.privateKey != "" {
		t.Error("PrivateKey should be empty initially")
	}

	// Check cursor starts at 0
	if model.cursor != 0 {
		t.Errorf("Expected cursor 0, got %d", model.cursor)
	}
}
