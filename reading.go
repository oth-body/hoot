package main

import (
	"context"
	"fmt"
	"hoot/internal/relay"
	"hoot/tui"
	"log"
	"sort"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
)

// listPosts prints the user's 4 newest notes across all relays.
func listPosts(pubKey string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	events, failures := relay.QueryAll(ctx, getRelayList(), nostr.Filter{Authors: []string{pubKey}, Kinds: []int{1}, Limit: 4})
	for url, err := range failures {
		log.Printf("Error querying relay %s: %v", url, err)
	}
	if len(events) > 4 {
		events = events[:4]
	}
	fmt.Println("Last 4 posts from your profile:")
	for _, ev := range events {
		fmt.Printf("Created: %s\nContent: %s\n\n",
			time.Unix(int64(ev.CreatedAt), 0).Format(time.RFC1123), ev.Content)
	}
}

// feedLimit is how many posts the feed screen shows.
const feedLimit = 20

// eventToFeedPost converts a Nostr event to the TUI's display struct.
func eventToFeedPost(ev *nostr.Event) tui.FeedPost {
	return tui.FeedPost{
		ID:        ev.ID,
		Kind:      ev.Kind,
		Author:    ev.PubKey,
		Content:   ev.Content,
		CreatedAt: time.Unix(int64(ev.CreatedAt), 0).Format("Jan 2 15:04"),
	}
}

// newestFirst sorts events by created_at descending, de-duplicates by ID,
// and truncates to limit.
func newestFirst(events []*nostr.Event, limit int) []*nostr.Event {
	seen := make(map[string]bool, len(events))
	out := events[:0:0]
	for _, ev := range events {
		if ev == nil || seen[ev.ID] {
			continue
		}
		seen[ev.ID] = true
		out = append(out, ev)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// queryRelays queries every relay in parallel and returns the union of
// matching events (de-duplicated, newest first). Unreachable relays are
// skipped.
func queryRelays(ctx context.Context, relays []string, filters ...nostr.Filter) []*nostr.Event {
	events, _ := relay.QueryAll(ctx, relays, filters...)
	return events
}

// maxFollowAuthors caps the authors filter for the following feed; relays
// reject very large filters.
const maxFollowAuthors = 500

// errNoContacts is returned for the following feed when the user has no
// contact list.
var errNoContacts = fmt.Errorf("you don't follow anyone yet (no contact list found); press g for the global feed")

// getFeedPosts returns the newest kind-1 posts, newest first, with author
// names: from everyone (global) or from the people the user follows.
//
// Relays are queried first; the local cache is only a fallback for when no
// relay answers (global feed only).
func getFeedPosts(following bool) ([]tui.FeedPost, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	filter := nostr.Filter{Kinds: []int{1}, Limit: feedLimit}
	if following {
		me := currentPubKey()
		if me == "" {
			return nil, fmt.Errorf("not signed in")
		}
		contacts, err := getContacts(ctx, me)
		if err != nil {
			return nil, err
		}
		if len(contacts) == 0 {
			return nil, errNoContacts
		}
		if len(contacts) > maxFollowAuthors {
			contacts = contacts[:maxFollowAuthors]
		}
		filter.Authors = contacts
	}

	events := queryRelays(ctx, getRelayList(), filter)
	if eventCache != nil {
		for _, ev := range events {
			_ = eventCache.StoreEvent(ev, 24*time.Hour)
		}
		if len(events) == 0 && !following {
			cached, _ := eventCache.GetEventsByPubKey("", 1, feedLimit)
			events = cached
		}
	}

	var posts []tui.FeedPost
	for _, ev := range newestFirst(events, feedLimit) {
		posts = append(posts, eventToFeedPost(ev))
	}
	return withNames(posts), nil
}

// dmLimit caps how many DMs are fetched and shown.
const dmLimit = 50

// dmFilters returns the two filters needed to see a user's whole NIP-04
// conversation history: messages they received (#p) and messages they sent
// (authors). The previous single filter {kinds:[4], limit:50} asked relays
// for the 50 newest DMs *on the whole network* and then discarded the ones
// that didn't involve the user — which in practice was nearly all of them.
func dmFilters(publicKey string) []nostr.Filter {
	return []nostr.Filter{
		{Kinds: []int{4}, Tags: nostr.TagMap{"p": []string{publicKey}}, Limit: dmLimit},
		{Kinds: []int{4}, Authors: []string{publicKey}, Limit: dmLimit},
	}
}

// decryptDM turns a kind-4 event into a display post if it involves the
// user. NIP-04's shared secret is ECDH(our privkey, *the other party's*
// pubkey): for an incoming DM that's the author, for an outgoing DM it's the
// p-tagged recipient. The old code always used the author, so the user's own
// sent messages could never be decrypted and silently vanished.
func decryptDM(ev *nostr.Event, privateKey, publicKey string) (tui.FeedPost, bool) {
	var recipient string
	if p := ev.Tags.GetFirst([]string{"p"}); p != nil && len(*p) > 1 {
		recipient = (*p)[1]
	}

	var counterparty, label string
	switch {
	case ev.PubKey == publicKey:
		if recipient == "" {
			return tui.FeedPost{}, false
		}
		counterparty = recipient
		label = "to " + shortKey(recipient)
	case recipient == publicKey:
		counterparty = ev.PubKey
		label = "from"
	default:
		return tui.FeedPost{}, false
	}

	ss, err := nip04.ComputeSharedSecret(counterparty, privateKey)
	if err != nil {
		return tui.FeedPost{}, false
	}
	plain, err := nip04.Decrypt(ev.Content, ss)
	if err != nil {
		return tui.FeedPost{}, false
	}
	return tui.FeedPost{
		Author:    ev.PubKey,
		Content:   fmt.Sprintf("[DM %s]: %s", label, plain),
		CreatedAt: time.Unix(int64(ev.CreatedAt), 0).Format("Jan 2 15:04"),
	}, true
}

// shortKey returns the first 8 chars of a key followed by "...", without
// panicking on short input.
func shortKey(k string) string {
	if len(k) > 8 {
		return k[:8] + "..."
	}
	return k
}

// getDMs returns the user's NIP-04 direct messages (sent and received),
// newest first, with author names.
func getDMs(privateKey string) ([]tui.FeedPost, error) {
	publicKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	events := newestFirst(queryRelays(ctx, getRelayList(), dmFilters(publicKey)...), dmLimit)

	var dms []tui.FeedPost
	for _, ev := range events {
		if post, ok := decryptDM(ev, privateKey, publicKey); ok {
			dms = append(dms, post)
		}
	}
	return withNames(dms), nil
}

// getReactions returns replies (kind 1) and reactions (kind 7) to an event,
// newest first. ref may be hex, note1… or nevent1… (whose relay hints are
// queried too).
func getReactions(ref string) ([]tui.FeedPost, error) {
	er, err := parseEventRef(ref)
	if err != nil {
		return nil, err
	}
	filter := nostr.Filter{
		Kinds: []int{7, 1},
		Tags:  nostr.TagMap{"e": []string{er.ID}},
		Limit: 50,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var out []tui.FeedPost
	for _, ev := range newestFirst(queryRelays(ctx, append(getRelayList(), er.Relays...), filter), 50) {
		p := eventToFeedPost(ev)
		if ev.Kind == 7 {
			r := ev.Content
			if r == "" || r == "+" {
				r = "❤"
			}
			p.Content = fmt.Sprintf("[Reacted: %s]", r)
		}
		out = append(out, p)
	}
	return withNames(out), nil
}

// getProfile prints the newest kind 0 (profile) event for pubKey.
func getProfile(pubKey string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	events, failures := relay.QueryAll(ctx, getRelayList(), nostr.Filter{Authors: []string{pubKey}, Kinds: []int{0}, Limit: 1})
	if len(events) == 0 {
		for url, err := range failures {
			log.Printf("Error querying relay %s: %v", url, err)
		}
		fmt.Println("Profile not found")
		return
	}
	fmt.Println("Your profile:")
	fmt.Println(events[0].Content)
}
