package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDefaultRelays pins the default relay list, which README.md and the
// docs repeat, so a change here is deliberate and the docs get updated.
func TestDefaultRelays(t *testing.T) {
	want := []string{"wss://relay.damus.io", "wss://nos.lol", "wss://relay.primal.net"}
	if strings.Join(defaultRelays, " ") != strings.Join(want, " ") {
		t.Fatalf("defaultRelays = %v, want %v (update README.md and the docs too)", defaultRelays, want)
	}
	// Paid-to-write and search-only relays reject or ignore a new user's
	// posts; they don't belong in the defaults.
	for _, r := range defaultRelays {
		for _, bad := range []string{"nostr.wine", "nostr.band"} {
			if strings.Contains(r, bad) {
				t.Errorf("default relay %q is paid or search-only", r)
			}
		}
	}
}

// relays.example.txt documents the defaults; it must parse (comments and
// all) to exactly the same list.
func TestRelaysExampleMatchesDefaults(t *testing.T) {
	data, err := os.ReadFile("relays.example.txt")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "relays.txt"), data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	got, err := loadRelays()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, " ") != strings.Join(defaultRelays, " ") {
		t.Fatalf("relays.example.txt parses to %v, defaults are %v", got, defaultRelays)
	}
}

// TestDefaultRelaysAreUnique pins the dedup behavior of defaultRelays.
// A historical bug listed one relay twice, causing every post to be sent
// to the same relay in parallel. The fix is an init() that dedupes; this
// test pins it.
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
