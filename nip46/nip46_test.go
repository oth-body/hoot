package nip46

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestGenerateConnectURIMultipleRelays ensures the URI advertises
// every relay passed in as a separate relay= query parameter,
// per NIP-46. Earlier versions encoded only a single relay. When
// the user's first configured relay was down at scan-time, this
// meant a websocket error and a broken login.
func TestGenerateConnectURIMultipleRelays(t *testing.T) {
	relays := []string{
		"wss://relay.damus.io",
		"wss://relay.nostr.band",
		"wss://nostr.wine",
	}
	uri, session, err := GenerateConnectURI(relays, "hoot-test")
	if err != nil {
		t.Fatalf("GenerateConnectURI: %v", err)
	}

	// Must be a nostrconnect:// URI.
	if !strings.HasPrefix(uri, "nostrconnect://") {
		t.Fatalf("URI does not start with nostrconnect://: %s", uri)
	}

	// Parse and inspect relay params.
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("URI not parseable: %v", err)
	}
	got := u.Query()["relay"]
	if len(got) != len(relays) {
		t.Fatalf("URI contains %d relay= params, want %d (got: %v)",
			len(got), len(relays), got)
	}
	wantSet := map[string]struct{}{}
	for _, r := range relays {
		wantSet[r] = struct{}{}
	}
	for _, r := range got {
		if _, ok := wantSet[r]; !ok {
			t.Errorf("URI contains unexpected relay %q", r)
		}
		delete(wantSet, r)
	}
	if len(wantSet) > 0 {
		missing := []string{}
		for r := range wantSet {
			missing = append(missing, r)
		}
		t.Errorf("URI is missing relays: %v", missing)
	}

	// Session must carry the full relay list.
	if len(session.RelayURLs) != len(relays) {
		t.Errorf("session.RelayURLs = %v, want %v", session.RelayURLs, relays)
	}

	// Client keypair must be set so the URI encodes a valid pubkey.
	if len(session.ClientPublicKey) != 64 {
		t.Errorf("session.ClientPublicKey not 64 hex chars: %q", session.ClientPublicKey)
	}
	if len(session.ClientPrivateKey) != 64 {
		t.Errorf("session.ClientPrivateKey not 64 hex chars (got %d)", len(session.ClientPrivateKey))
	}

	// The client pubkey in the URI must match session.ClientPublicKey.
	host := u.Host
	if host != session.ClientPublicKey {
		t.Errorf("URI host %q != session client pubkey %q", host, session.ClientPublicKey)
	}
}

// TestGenerateConnectURIDedupsRelays makes sure we don't emit
// the same relay twice if the user passes duplicates — relay
// dedupe is also done at the defaultRelays level, but the helper
// should be robust on its own.
func TestGenerateConnectURIDedupsRelays(t *testing.T) {
	relays := []string{
		"wss://relay.damus.io",
		"wss://relay.damus.io", // dup
		"wss://nostr.wine",
	}
	uri, _, err := GenerateConnectURI(relays, "hoot-test")
	if err != nil {
		t.Fatalf("GenerateConnectURI: %v", err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("URI not parseable: %v", err)
	}
	got := u.Query()["relay"]
	if len(got) != 2 {
		t.Errorf("expected 2 distinct relay= params (after dedup), got %d: %v", len(got), got)
	}
}

// TestGenerateConnectURISingleRelayFallback exercises the case
// where the caller has no relays configured. We fall back to
// wss://relay.damus.io so the URI is still valid; the user can
// override it via getRelayList() in hoot.
func TestGenerateConnectURISingleRelayFallback(t *testing.T) {
	uri, session, err := GenerateConnectURI(nil, "hoot-test")
	if err != nil {
		t.Fatalf("GenerateConnectURI(nil): %v", err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("URI not parseable: %v", err)
	}
	got := u.Query()["relay"]
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 fallback relay, got %d", len(got))
	}
	if got[0] != "wss://relay.damus.io" {
		t.Errorf("fallback relay = %q, want wss://relay.damus.io", got[0])
	}
	if len(session.RelayURLs) != 1 || session.RelayURLs[0] != "wss://relay.damus.io" {
		t.Errorf("session.RelayURLs = %v, want [wss://relay.damus.io]", session.RelayURLs)
	}
}

// TestDialRelaysContinuesOnIndividualFailure verifies that
// dialRelays returns the subset of relays that actually came up
// when some dials fail (rather than failing the whole session).
// This is the bug behind "got a websocket error" — previously the
// session picked exactly one relay and any failure on it killed
// the login.
func TestDialRelaysContinuesOnIndividualFailure(t *testing.T) {
	s := &Session{
		ClientPublicKey: "00" + strings.Repeat("11", 31),
		RelayURLs: []string{
			"wss://invalid-relay-does-not-exist-1.invalid",
			"wss://invalid-relay-does-not-exist-2.invalid",
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got := s.dialRelays(ctx, 2*time.Second)
	if len(got) != 0 {
		t.Errorf("dialRelays = %v, want empty (no reachable URLs)", got)
	}
	// Should not panic, should clean up. (Subscriptions can't be
	// opened without a connection so WaitForConnection would error
	// next — but we stop here.)
}
