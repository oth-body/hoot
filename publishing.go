package main

import (
	"context"
	"fmt"
	"hoot/internal/relay"
	"log"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// signEvent signs ev as the current user: via the NIP-46 remote signer if
// one is connected, otherwise with the local key. It sets ev.PubKey.
func signEvent(ev *nostr.Event) error {
	if ev.Tags == nil {
		ev.Tags = nostr.Tags{}
	}
	if nip46Session != nil {
		ev.PubKey = nip46Session.UserPublicKey
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := nip46Session.SignEvent(ctx, ev); err != nil {
			return fmt.Errorf("remote signing failed: %w", err)
		}
		return nil
	}
	if localPrivateKey == "" {
		return fmt.Errorf("no active session or local key")
	}
	pk, err := nostr.GetPublicKey(localPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to get public key: %w", err)
	}
	ev.PubKey = pk
	if err := ev.Sign(localPrivateKey); err != nil {
		return fmt.Errorf("failed to sign event: %w", err)
	}
	return nil
}

// signAndPublish signs ev as the current user and publishes it to the
// user's relays plus any extra relays (e.g. hints for the event being
// replied to).
func signAndPublish(ev *nostr.Event, extraRelays ...string) error {
	if err := signEvent(ev); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, err := relay.PublishAll(ctx, append(getRelayList(), extraRelays...), *ev)
	return err
}

// publishPostTUI publishes a note as the current user. #hashtags become "t"
// tags, like `hoot -m`.
func publishPostTUI(content string) error {
	ev := nostr.Event{Kind: 1, Content: content, CreatedAt: nostr.Now(), Tags: hashtagTags(content)}
	return signAndPublish(&ev)
}

// fetchEvent finds an event by ID: the local cache first, then relays.
func fetchEvent(id string) (*nostr.Event, error) {
	if eventCache != nil {
		if ev, err := eventCache.GetEvent(id); err == nil && ev != nil {
			return ev, nil
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	evs := queryRelays(ctx, getRelayList(), nostr.Filter{IDs: []string{id}})
	if len(evs) == 0 {
		return nil, fmt.Errorf("couldn't find the post on your relays")
	}
	return evs[0], nil
}

// replyTags builds NIP-10 tags for a reply to parent: marked "root" and
// "reply" e-tags (a reply to a top-level post only needs "root"), and p-tags
// for the parent's author plus everyone the parent already mentions.
func replyTags(parent *nostr.Event, me string) nostr.Tags {
	rootID := ""
	for _, t := range parent.Tags {
		if len(t) >= 4 && t[0] == "e" && t[3] == "root" {
			rootID = t[1]
			break
		}
	}
	if rootID == "" {
		// Deprecated positional form: the first e-tag is the root.
		for _, t := range parent.Tags {
			if len(t) >= 2 && t[0] == "e" {
				rootID = t[1]
				break
			}
		}
	}

	var tags nostr.Tags
	if rootID == "" || rootID == parent.ID {
		tags = append(tags, nostr.Tag{"e", parent.ID, "", "root", parent.PubKey})
	} else {
		tags = append(tags,
			nostr.Tag{"e", rootID, "", "root"},
			nostr.Tag{"e", parent.ID, "", "reply", parent.PubKey})
	}

	seen := map[string]bool{me: true}
	addP := func(pk string) {
		if pk != "" && !seen[pk] && nostr.IsValid32ByteHex(pk) {
			seen[pk] = true
			tags = append(tags, nostr.Tag{"p", pk})
		}
	}
	addP(parent.PubKey)
	for _, t := range parent.Tags {
		if len(t) >= 2 && t[0] == "p" {
			addP(t[1])
		}
	}
	return tags
}

// publishReply replies to the event with the given ID.
func publishReply(parentID, content string) error {
	parent, err := fetchEvent(parentID)
	if err != nil {
		return err
	}
	ev := nostr.Event{Kind: 1, Content: content, CreatedAt: nostr.Now()}
	ev.Tags = append(replyTags(parent, currentPubKey()), hashtagTags(content)...)
	return signAndPublish(&ev)
}

// publishReaction likes (NIP-25 "+") the event with the given ID.
func publishReaction(targetID string) error {
	target, err := fetchEvent(targetID)
	if err != nil {
		return err
	}
	ev := nostr.Event{
		Kind:      7,
		Content:   "+",
		CreatedAt: nostr.Now(),
		Tags: nostr.Tags{
			{"e", target.ID},
			{"p", target.PubKey},
			{"k", fmt.Sprint(target.Kind)},
		},
	}
	return signAndPublish(&ev)
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
