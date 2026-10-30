package cache

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// Regression: New failed on a fresh install because the config dir didn't
// exist yet.
func TestNewCreatesMissingDirAndRoundTrips(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does", "not", "exist")
	c, err := New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer c.Close()

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	ev := &nostr.Event{PubKey: pk, CreatedAt: nostr.Now(), Kind: 1, Tags: nostr.Tags{{"t", "x"}}, Content: "hi"}
	if err := ev.Sign(sk); err != nil {
		t.Fatal(err)
	}
	if err := c.StoreEvent(ev, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := c.GetEventsByPubKey("", 1, 10)
	if err != nil || len(got) != 1 || got[0].ID != ev.ID || got[0].Content != "hi" {
		t.Fatalf("GetEventsByPubKey = %+v, %v", got, err)
	}

	if err := c.StoreProfile(pk, "n", "a", "p", "n@x", 1, time.Hour); err != nil {
		t.Fatal(err)
	}
	if p, err := c.GetProfile(pk); err != nil || p == nil || p.Name != "n" {
		t.Fatalf("GetProfile = %+v, %v", p, err)
	}
}

// Regression: expires_at was bound as a time.Time (stored as TEXT), so the
// integer comparisons in queries and CleanupExpired never matched.
func TestExpiredEntriesAreHiddenAndCleaned(t *testing.T) {
	c, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	ev := &nostr.Event{PubKey: pk, CreatedAt: nostr.Now(), Kind: 1, Tags: nostr.Tags{}, Content: "short-lived"}
	if err := ev.Sign(sk); err != nil {
		t.Fatal(err)
	}
	// Store with a real TTL, then force it into the past.
	if err := c.StoreEvent(ev, time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := c.db.Exec(`UPDATE events SET expires_at = ? WHERE id = ?`, time.Now().Add(-time.Minute).Unix(), ev.ID); err != nil {
		t.Fatal(err)
	}
	if got, _ := c.GetEvent(ev.ID); got != nil {
		t.Fatal("expired event still returned")
	}
	if err := c.CleanupExpired(); err != nil {
		t.Fatal(err)
	}
	events, _, _, err := c.Stats()
	if err != nil || events != 0 {
		t.Fatalf("events after cleanup = %d, %v", events, err)
	}

	// A live entry is returned.
	if err := c.StoreEvent(ev, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got, err := c.GetEvent(ev.ID); err != nil || got == nil {
		t.Fatalf("live event missing: %v", err)
	}
}
