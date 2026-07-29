package main

import "testing"

func TestBuzzPubkeyAcceptsHex(t *testing.T) {
	key := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	got, err := buzzPubkey(key)
	if err != nil {
		t.Fatalf("buzzPubkey returned error: %v", err)
	}
	if got != key {
		t.Fatalf("got %q, want %q", got, key)
	}
}

func TestBuzzPubkeyRejectsInvalidInput(t *testing.T) {
	if _, err := buzzPubkey("not-a-pubkey"); err == nil {
		t.Fatal("buzzPubkey accepted malformed recipient")
	}
}

func TestBuzzRelayUsesEnvironment(t *testing.T) {
	t.Setenv("BUZZ_RELAY_URL", "wss://buzz.example")
	got, err := buzzRelay("")
	if err != nil {
		t.Fatalf("buzzRelay returned error: %v", err)
	}
	if got != "wss://buzz.example" {
		t.Fatalf("got %q", got)
	}
}
