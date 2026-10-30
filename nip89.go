package main

import (
	"context"
	"fmt"
	"hoot/internal/relay"
	"strconv"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// registerAsHandler registers the app as a handler for specific kinds.
func registerAsHandler(privateKey, publicKey string, kinds []int, platforms map[string]string) error {
	// Create a kind 31990 event for handler registration (NIP-89)
	event := nostr.Event{
		PubKey:    publicKey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      31990,
		Tags:      nostr.Tags{{"d", "hoot"}},
		Content:   "",
	}

	// Add tags for supported kinds and platforms
	for _, kind := range kinds {
		event.Tags = append(event.Tags, nostr.Tag{"k", fmt.Sprintf("%d", kind)})
	}
	for platform, url := range platforms {
		event.Tags = append(event.Tags, nostr.Tag{"p", platform, url})
	}

	// Sign the event
	if err := event.Sign(privateKey); err != nil {
		return fmt.Errorf("failed to sign handler registration event: %w", err)
	}

	return publishAndReport(getRelayList(), event, "handler registration")
}

// recommendApp publishes a recommendation for an app for a specific kind.
func recommendApp(privateKey, publicKey, handlerPubKey, handlerDIdentifier string, kind int, relayHint, platform string) error {
	// Create a kind 1985 event for app recommendation
	event := nostr.Event{
		PubKey:    publicKey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1985,
		Tags: nostr.Tags{
			{"a", fmt.Sprintf("%d:%s:%s", kind, handlerPubKey, handlerDIdentifier)},
			{"p", platform},
		},
		Content: relayHint,
	}

	// Sign the event
	if err := event.Sign(privateKey); err != nil {
		return fmt.Errorf("failed to sign app recommendation event: %w", err)
	}

	return publishAndReport(getRelayList(), event, "app recommendation")
}

// findHandlers queries relays for NIP-89 handlers of a specific kind.
func findHandlers(kind int) ([]struct {
	PubKey         string
	SupportedKinds []int
	Platforms      map[string]string
}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	events, _ := relay.QueryAll(ctx, getRelayList(), nostr.Filter{
		Kinds: []int{31990},
		Tags:  nostr.TagMap{"k": []string{fmt.Sprintf("%d", kind)}},
	})

	var handlers []struct {
		PubKey         string
		SupportedKinds []int
		Platforms      map[string]string
	}
	for _, ev := range events {
		handler := struct {
			PubKey         string
			SupportedKinds []int
			Platforms      map[string]string
		}{
			PubKey:    ev.PubKey,
			Platforms: make(map[string]string),
		}
		for _, tag := range ev.Tags {
			if len(tag) > 1 && tag[0] == "k" {
				if k, err := strconv.Atoi(tag[1]); err == nil {
					handler.SupportedKinds = append(handler.SupportedKinds, k)
				}
			} else if len(tag) > 2 && tag[0] == "p" {
				handler.Platforms[tag[1]] = tag[2]
			}
		}
		handlers = append(handlers, handler)
	}
	return handlers, nil
}
