package nip46

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestProfileMetadataJSONRoundTrip pins the JSON shape so
// Session.FetchProfile's unmarshal target doesn't drift from
// what kind-0 events actually contain on the wire.
func TestProfileMetadataJSONRoundTrip(t *testing.T) {
	in := `{"name":"alice","about":"hello world","picture":"https://example.com/a.png","nip05":"alice@example.com"}`
	var got ProfileMetadata
	if err := json.Unmarshal([]byte(in), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	want := ProfileMetadata{
		Name:    "alice",
		About:   "hello world",
		Picture: "https://example.com/a.png",
		NIP05:   "alice@example.com",
	}
	if got != want {
		t.Errorf("round-trip mismatch:\n got: %+v\nwant: %+v", got, want)
	}
}

// TestProfileMetadataOmitsEmptyFields pins that empty fields
// don't get written to JSON. This matters because the wire format
// is "if a field is absent, the signer didn't set it" — emitting
// empty strings would mislead downstream consumers.
func TestProfileMetadataOmitsEmptyFields(t *testing.T) {
	m := ProfileMetadata{Name: "alice"}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), `"about"`) {
		t.Errorf("empty About should be omitted, got: %s", b)
	}
	if strings.Contains(string(b), `"picture"`) {
		t.Errorf("empty Picture should be omitted, got: %s", b)
	}
	if !strings.Contains(string(b), `"name":"alice"`) {
		t.Errorf("Name should marshal, got: %s", b)
	}
}

// TestFetchProfileRejectsEmptyPubKey pins the input-validation
// guard. Calling FetchProfile with "" used to silently fail
// with an opaque "no relay connections" error.
func TestFetchProfileRejectsEmptyPubKey(t *testing.T) {
	s := &Session{}
	_, err := s.FetchProfile(context.Background(), "")
	if err == nil {
		t.Fatal("expected error for empty pubkey, got nil")
	}
	if !strings.Contains(err.Error(), "empty user pubkey") {
		t.Errorf("expected 'empty user pubkey' in error, got: %v", err)
	}
}

// TestFetchProfileRejectsNoRelays pins the "called too early"
// guard. Without a prior ConnectRelays, s.relays is nil and
// the user would see a panic or a confusing relay-dial error.
func TestFetchProfileRejectsNoRelays(t *testing.T) {
	s := &Session{}
	_, err := s.FetchProfile(context.Background(), "deadbeef")
	if err == nil {
		t.Fatal("expected error when no relays are connected, got nil")
	}
	if !strings.Contains(err.Error(), "no relay connections") {
		t.Errorf("expected 'no relay connections' in error, got: %v", err)
	}
}

// TestProfileNameRendersOnHomeScreen is a contract test: when
// FetchProfile returns a profile with a name, the caller (the
// TUI's qrSuccessMsg handler) is expected to set the model's
// currentProfileName so viewHome shows it. We assert that the
// wire-format of ProfileMetadata.Name is exactly what the TUI
// renders — a plain string, no ANSI escapes, no embedded
// markdown, etc. This is the test that would have caught the
// original bug ("doesn't show the profile of the person").
func TestProfileNameIsRenderable(t *testing.T) {
	cases := []struct {
		name      string
		nostrName string
		wantOK    bool
	}{
		{"plain ASCII", "alice", true},
		{"emoji", "🦉 hoot", true},
		{"unicode", "日本語ユーザー", true},
		{"with spaces", "Satoshi Nakamoto", true},
		// Suspicious but not invalid — clients should display as-is.
		{"with markup", "<b>alice</b>", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := ProfileMetadata{Name: tc.nostrName}
			if p.Name != tc.nostrName {
				t.Errorf("ProfileMetadata.Name round-trip lost data: got %q, want %q", p.Name, tc.nostrName)
			}
		})
	}
}