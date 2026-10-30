package main

import (
	"context"
	"fmt"
	"hoot/internal/relay"
	"log"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// publishPostTUI publishes a note using either NIP-46 or local key
func publishPostTUI(content string) error {
	var event nostr.Event
	var err error
	event.Kind = 1
	event.Content = content
	event.CreatedAt = nostr.Now()
	event.Tags = nostr.Tags{}

	// If NIP-46 session is active, use it
	if nip46Session != nil {
		event.PubKey = nip46Session.UserPublicKey
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := nip46Session.SignEvent(ctx, &event); err != nil {
			return fmt.Errorf("remote signing failed: %w", err)
		}
	} else {
		// Use local key
		if localPrivateKey == "" {
			return fmt.Errorf("no active session or local key")
		}
		event.PubKey, err = nostr.GetPublicKey(localPrivateKey)
		if err != nil {
			return fmt.Errorf("failed to get public key: %w", err)
		}
		if err := event.Sign(localPrivateKey); err != nil {
			return fmt.Errorf("failed to sign event: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, err = relay.PublishAll(ctx, getRelayList(), event)
	return err
}

// editProfile publishes a new kind 0 (profile) event with the updated profile info.
func editProfile(privateKey, newContent, pubKey string, relays []string) {
	event := nostr.Event{
		PubKey:    pubKey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      0,
		Content:   newContent,
		Tags:      nostr.Tags{},
	}
	if err := event.Sign(privateKey); err != nil {
		log.Fatalf("Failed to sign profile event: %v", err)
	}
	if err := publishAndReport(relays, event, "profile update"); err != nil {
		log.Printf("Profile update failed: %v", err)
	}
}

// publishAndReport publishes ev to relays in parallel and prints one line
// per relay. It returns an error only if no relay accepted the event.
func publishAndReport(relays []string, ev nostr.Event, what string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	accepted, failures, err := relay.PublishAll(ctx, relays, ev)
	for _, u := range accepted {
		fmt.Printf("Successfully published %s to relay: %s\n", what, u)
	}
	for u, ferr := range failures {
		fmt.Printf("Failed to publish to relay %s: %v\n", u, ferr)
	}
	if err != nil {
		return fmt.Errorf("%w (%d attempted)", err, len(failures))
	}
	if len(failures) > 0 {
		fmt.Printf("Published to %d relay(s); %d failed\n", len(accepted), len(failures))
	}
	return nil
}

// publishNote publishes a signed event to all relays in parallel, printing
// a line per relay, and returns an error if no relay accepted it.
func publishNote(ctx context.Context, relays []string, event nostr.Event) error {
	_ = ctx // publishAndReport applies its own timeout
	return publishAndReport(relays, event, "note")
}
