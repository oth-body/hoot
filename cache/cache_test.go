package cache

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

func TestNew(t *testing.T) {
	// Create temp directory
	tempDir, err := os.MkdirTemp("", "hoot-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cache, err := New(tempDir)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Verify database file was created
	dbPath := filepath.Join(tempDir, "hoot_cache.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Error("Database file was not created")
	}
}

func TestStoreAndGetEvent(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hoot-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cache, err := New(tempDir)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Create test event
	event := &nostr.Event{
		ID:        "test-event-id-1",
		PubKey:    "test-pubkey",
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1,
		Content:   "Test content",
		Sig:       "test-signature",
		Tags:      nostr.Tags{{"tag1", "value1"}},
	}

	// Store event with 1 hour TTL
	err = cache.StoreEvent(event, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to store event: %v", err)
	}

	// Retrieve event
	retrieved, err := cache.GetEvent(event.ID)
	if err != nil {
		t.Fatalf("Failed to get event: %v", err)
	}

	if retrieved == nil {
		t.Fatal("Expected to retrieve event, got nil")
	}

	if retrieved.ID != event.ID {
		t.Errorf("Expected ID %s, got %s", event.ID, retrieved.ID)
	}

	if retrieved.Content != event.Content {
		t.Errorf("Expected content %s, got %s", event.Content, retrieved.Content)
	}

	if len(retrieved.Tags) != len(event.Tags) {
		t.Errorf("Expected %d tags, got %d", len(event.Tags), len(retrieved.Tags))
	}
}

func TestEventExpiry(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hoot-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cache, err := New(tempDir)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	event := &nostr.Event{
		ID:        "test-event-expiring",
		PubKey:    "test-pubkey",
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1,
		Content:   "This will expire",
		Sig:       "test-signature",
		Tags:      nostr.Tags{},
	}

	// Store with very short TTL (100ms)
	err = cache.StoreEvent(event, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to store event: %v", err)
	}

	// Should be retrievable immediately
	retrieved, err := cache.GetEvent(event.ID)
	if err != nil {
		t.Fatalf("Failed to get event: %v", err)
	}
	if retrieved == nil {
		t.Fatal("Expected to retrieve event immediately, got nil")
	}

	// Wait for expiry
	time.Sleep(150 * time.Millisecond)

	// Should be expired now
	retrieved, err = cache.GetEvent(event.ID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if retrieved != nil {
		t.Error("Expected event to be expired, but it was retrieved")
	}
}

func TestGetEventsByPubKey(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hoot-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cache, err := New(tempDir)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Store multiple events from same pubkey
	pubkey := "test-pubkey-filter"
	for i := 0; i < 5; i++ {
		event := &nostr.Event{
			ID:        "test-event-filter-" + string(rune('0'+i)),
			PubKey:    pubkey,
			CreatedAt: nostr.Timestamp(time.Now().Unix() - int64(i*60)),
			Kind:      1,
			Content:   "Test content",
			Sig:       "sig",
			Tags:      nostr.Tags{},
		}
		err = cache.StoreEvent(event, 1*time.Hour)
		if err != nil {
			t.Fatalf("Failed to store event %d: %v", i, err)
		}
	}

	// Retrieve events by pubkey
	events, err := cache.GetEventsByPubKey(pubkey, 1, 10)
	if err != nil {
		t.Fatalf("Failed to get events by pubkey: %v", err)
	}

	if len(events) != 5 {
		t.Errorf("Expected 5 events, got %d", len(events))
	}

	// Test with limit
	events, err = cache.GetEventsByPubKey(pubkey, 1, 2)
	if err != nil {
		t.Fatalf("Failed to get events with limit: %v", err)
	}

	if len(events) != 2 {
		t.Errorf("Expected 2 events with limit, got %d", len(events))
	}
}

func TestStoreAndGetProfile(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hoot-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cache, err := New(tempDir)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Store profile
	pubkey := "test-profile-pubkey"
	err = cache.StoreProfile(pubkey, "Test User", "About me", "https://example.com/pic.jpg", "test@example.com", time.Now().Unix(), 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to store profile: %v", err)
	}

	// Retrieve profile
	profile, err := cache.GetProfile(pubkey)
	if err != nil {
		t.Fatalf("Failed to get profile: %v", err)
	}

	if profile == nil {
		t.Fatal("Expected to retrieve profile, got nil")
	}

	if profile.Name != "Test User" {
		t.Errorf("Expected name 'Test User', got %s", profile.Name)
	}

	if profile.About != "About me" {
		t.Errorf("Expected about 'About me', got %s", profile.About)
	}

	if profile.NIP05 != "test@example.com" {
		t.Errorf("Expected NIP05 'test@example.com', got %s", profile.NIP05)
	}
}

func TestProfileExpiry(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hoot-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cache, err := New(tempDir)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	pubkey := "test-profile-expiring"
	err = cache.StoreProfile(pubkey, "Test", "About", "", "", time.Now().Unix(), 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to store profile: %v", err)
	}

	// Should be retrievable immediately
	profile, err := cache.GetProfile(pubkey)
	if err != nil {
		t.Fatalf("Failed to get profile: %v", err)
	}
	if profile == nil {
		t.Fatal("Expected to retrieve profile immediately")
	}

	// Wait for expiry
	time.Sleep(150 * time.Millisecond)

	// Should be expired
	profile, err = cache.GetProfile(pubkey)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if profile != nil {
		t.Error("Expected profile to be expired")
	}
}

func TestUpdateRelayStats(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hoot-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cache, err := New(tempDir)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	relayURL := "wss://test.relay.com"

	// Record successful request
	err = cache.UpdateRelayStats(relayURL, 100, true)
	if err != nil {
		t.Fatalf("Failed to update relay stats: %v", err)
	}

	// Record failed request
	err = cache.UpdateRelayStats(relayURL, 200, false)
	if err != nil {
		t.Fatalf("Failed to update relay stats: %v", err)
	}

	// Get stats
	stats, err := cache.GetRelayStats(relayURL)
	if err != nil {
		t.Fatalf("Failed to get relay stats: %v", err)
	}

	if stats == nil {
		t.Fatal("Expected to retrieve stats, got nil")
	}

	if stats.URL != relayURL {
		t.Errorf("Expected URL %s, got %s", relayURL, stats.URL)
	}

	if stats.TotalRequests != 2 {
		t.Errorf("Expected 2 total requests, got %d", stats.TotalRequests)
	}

	if stats.SuccessfulRequests != 1 {
		t.Errorf("Expected 1 successful request, got %d", stats.SuccessfulRequests)
	}

	// Success rate should be 0.5 (1 success out of 2)
	if stats.SuccessRate < 0.49 || stats.SuccessRate > 0.51 {
		t.Errorf("Expected success rate ~0.5, got %f", stats.SuccessRate)
	}
}

func TestCleanupExpired(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hoot-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cache, err := New(tempDir)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Store event that expires quickly
	event1 := &nostr.Event{
		ID:        "event-expiring",
		PubKey:    "pubkey",
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1,
		Content:   "Will expire",
		Sig:       "sig",
		Tags:      nostr.Tags{},
	}
	err = cache.StoreEvent(event1, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("Failed to store event1: %v", err)
	}

	// Store event that doesn't expire
	event2 := &nostr.Event{
		ID:        "event-permanent",
		PubKey:    "pubkey",
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1,
		Content:   "Will not expire",
		Sig:       "sig",
		Tags:      nostr.Tags{},
	}
	err = cache.StoreEvent(event2, 0) // No expiry
	if err != nil {
		t.Fatalf("Failed to store event2: %v", err)
	}

	// Wait for first event to expire
	time.Sleep(150 * time.Millisecond)

	// Run cleanup
	err = cache.CleanupExpired()
	if err != nil {
		t.Fatalf("Failed to cleanup expired: %v", err)
	}

	// First event should be gone
	retrieved1, err := cache.GetEvent(event1.ID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if retrieved1 != nil {
		t.Error("Expected expired event to be cleaned up")
	}

	// Second event should still exist
	retrieved2, err := cache.GetEvent(event2.ID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if retrieved2 == nil {
		t.Error("Expected non-expired event to still exist")
	}
}

func TestClear(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hoot-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cache, err := New(tempDir)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Store some data
	event := &nostr.Event{
		ID:        "event-to-clear",
		PubKey:    "pubkey",
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1,
		Content:   "Test",
		Sig:       "sig",
		Tags:      nostr.Tags{},
	}
	err = cache.StoreEvent(event, 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to store event: %v", err)
	}

	err = cache.StoreProfile("pubkey", "Name", "About", "", "", time.Now().Unix(), 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to store profile: %v", err)
	}

	// Clear all
	err = cache.Clear()
	if err != nil {
		t.Fatalf("Failed to clear cache: %v", err)
	}

	// Verify data is gone
	retrieved, err := cache.GetEvent(event.ID)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if retrieved != nil {
		t.Error("Expected event to be cleared")
	}

	profile, err := cache.GetProfile("pubkey")
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if profile != nil {
		t.Error("Expected profile to be cleared")
	}
}

func TestStats(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "hoot-cache-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	cache, err := New(tempDir)
	if err != nil {
		t.Fatalf("Failed to create cache: %v", err)
	}
	defer cache.Close()

	// Store some data
	for i := 0; i < 3; i++ {
		event := &nostr.Event{
			ID:        "stats-event-" + string(rune('0'+i)),
			PubKey:    "pubkey",
			CreatedAt: nostr.Timestamp(time.Now().Unix()),
			Kind:      1,
			Content:   "Test",
			Sig:       "sig",
			Tags:      nostr.Tags{},
		}
		err = cache.StoreEvent(event, 1*time.Hour)
		if err != nil {
			t.Fatalf("Failed to store event: %v", err)
		}
	}

	err = cache.StoreProfile("pubkey1", "Name1", "", "", "", time.Now().Unix(), 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to store profile: %v", err)
	}

	err = cache.StoreProfile("pubkey2", "Name2", "", "", "", time.Now().Unix(), 1*time.Hour)
	if err != nil {
		t.Fatalf("Failed to store profile: %v", err)
	}

	err = cache.UpdateRelayStats("wss://relay1.com", 100, true)
	if err != nil {
		t.Fatalf("Failed to update relay stats: %v", err)
	}

	// Get stats
	events, profiles, relays, err := cache.Stats()
	if err != nil {
		t.Fatalf("Failed to get stats: %v", err)
	}

	if events != 3 {
		t.Errorf("Expected 3 events, got %d", events)
	}

	if profiles != 2 {
		t.Errorf("Expected 2 profiles, got %d", profiles)
	}

	if relays != 1 {
		t.Errorf("Expected 1 relay, got %d", relays)
	}
}
