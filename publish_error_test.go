package main

import (
	"context"
	"strings"
	"testing"
)

// TestPublishNoteAllRelaysFail pins that publishNote returns an error
// when no relay accepts the event. The original code returned nil even
// if every relay rejected the publish, so `hoot -m "..."` would print
// "Successfully published to relay" lines for failing relays AND exit 0.
// With the fix, all-fail returns a clear "failed to publish to any
// relay" error that the CLI surfaces to the user.
//
// We can't easily fake a relay connection without running an actual
// Nostr relay, so this test exercises the only path that's unit-
// testable: empty relay list. Empty list → no relays → success==0 →
// error returned.
func TestPublishNoteAllRelaysFail(t *testing.T) {
	err := publishNote(context.Background(), []string{}, nostr.Event{})
	if err == nil {
		t.Fatal("expected error when relay list is empty, got nil")
	}
	if !strings.Contains(err.Error(), "failed to publish to any relay") {
		t.Errorf("expected error mentioning 'failed to publish to any relay', got: %v", err)
	}
}

// TestPublishNoteNilRelays pins the nil-relays case (caller passed nil
// instead of an empty slice). Same expected behavior as empty slice:
// the loop doesn't iterate, no successes, error returned.
func TestPublishNoteNilRelays(t *testing.T) {
	err := publishNote(context.Background(), nil, nostr.Event{})
	if err == nil {
		t.Fatal("expected error when relay list is nil, got nil")
	}
}