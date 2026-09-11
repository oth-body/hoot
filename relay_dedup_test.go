package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

// TestDefaultRelaysAreUnique pins the dedup behavior of defaultRelays.
// A historical bug listed wss://nostr.wine twice, causing every post
// to be sent to the same relay in parallel. The fix is an init() that
// dedupes; this test pins it.
func TestDefaultRelaysAreUnique(t *testing.T) {
	seen := make(map[string]bool, len(defaultRelays))
	for _, r := range defaultRelays {
		if seen[r] {
			t.Errorf("defaultRelays contains duplicate entry: %q", r)
		}
		seen[r] = true
	}
	if len(defaultRelays) < 2 {
		t.Errorf("defaultRelays has too few entries (%d); expected at least 2", len(defaultRelays))
	}
	for _, r := range defaultRelays {
		if !strings.HasPrefix(r, "wss://") {
			t.Errorf("defaultRelays entry %q does not look like a wss URL", r)
		}
	}
}

// TestGenerateProfileIDIsUnique pins that two consecutive calls
// produce distinct IDs. With the original code, a crypto/rand.Read
// failure would produce "0000000000000000" for every call; with the
// fix, the fallback timestamp-derived ID is also distinct across calls
// within a single process (nanosecond resolution).
func TestGenerateProfileIDIsUnique(t *testing.T) {
	ids := make(map[string]bool, 1000)
	for i := 0; i < 1000; i++ {
		id := generateProfileID()
		if id == "" {
			t.Fatalf("generateProfileID returned empty string on iteration %d", i)
		}
		if len(id) != 16 {
			t.Errorf("generateProfileID returned %d chars (%q), expected 16", len(id), id)
		}
		if _, err := hex.DecodeString(id); err != nil {
			t.Errorf("generateProfileID returned non-hex string %q: %v", id, err)
		}
		if ids[id] {
			t.Fatalf("generateProfileID returned duplicate ID %q on iteration %d", id, i)
		}
		ids[id] = true
	}
}