package main

// Helpers that make the feed readable and navigable: author names, the
// user's contact list, event references in any common format, and hashtag
// tags.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode"

	"hoot/tui"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// profileTTL is how long fetched kind-0 names stay cached.
const profileTTL = 24 * time.Hour

// profileMeta is the subset of kind-0 content hoot displays.
type profileMeta struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	About       string `json:"about"`
	Picture     string `json:"picture"`
	NIP05       string `json:"nip05"`
}

func (p profileMeta) label() string {
	if s := strings.TrimSpace(p.DisplayName); s != "" {
		return s
	}
	return strings.TrimSpace(p.Name)
}

// resolveNames returns a display name for each pubkey that has one. Cached
// names are used first; the rest are fetched from relays in one query and
// cached.
func resolveNames(ctx context.Context, pubkeys []string) map[string]string {
	names := map[string]string{}
	var missing []string
	seen := map[string]bool{}
	for _, pk := range pubkeys {
		if pk == "" || seen[pk] {
			continue
		}
		seen[pk] = true
		if eventCache != nil {
			if p, err := eventCache.GetProfile(pk); err == nil && p != nil {
				if p.Name != "" {
					names[pk] = p.Name
				}
				continue // cached, even if nameless: don't refetch every time
			}
		}
		missing = append(missing, pk)
	}
	if len(missing) == 0 {
		return names
	}

	ctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	newest := map[string]*nostr.Event{}
	for _, ev := range queryRelays(ctx, getRelayList(), nostr.Filter{Kinds: []int{0}, Authors: missing}) {
		if cur, ok := newest[ev.PubKey]; !ok || ev.CreatedAt > cur.CreatedAt {
			newest[ev.PubKey] = ev
		}
	}
	for _, pk := range missing {
		var meta profileMeta
		var updated int64
		if ev := newest[pk]; ev != nil {
			_ = json.Unmarshal([]byte(ev.Content), &meta)
			updated = int64(ev.CreatedAt)
		}
		if l := meta.label(); l != "" {
			names[pk] = l
		}
		if eventCache != nil {
			_ = eventCache.StoreProfile(pk, meta.label(), meta.About, meta.Picture, meta.NIP05, updated, profileTTL)
		}
	}
	return names
}

// withNames fills in AuthorName for each post.
func withNames(posts []tui.FeedPost) []tui.FeedPost {
	pks := make([]string, 0, len(posts))
	for _, p := range posts {
		pks = append(pks, p.Author)
	}
	names := resolveNames(context.Background(), pks)
	for i := range posts {
		posts[i].AuthorName = names[posts[i].Author]
	}
	return posts
}

// currentPubKey is the signed-in user's hex pubkey, or "".
func currentPubKey() string {
	if nip46Session != nil && nip46Session.UserPublicKey != "" {
		return nip46Session.UserPublicKey
	}
	if localPrivateKey != "" {
		if pk, err := nostr.GetPublicKey(localPrivateKey); err == nil {
			return pk
		}
	}
	return ""
}

// getContacts returns the pubkeys in the user's newest contact list (kind 3).
func getContacts(ctx context.Context, pubkey string) ([]string, error) {
	events := queryRelays(ctx, getRelayList(), nostr.Filter{Kinds: []int{3}, Authors: []string{pubkey}, Limit: 1})
	if len(events) == 0 {
		return nil, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, t := range events[0].Tags {
		if len(t) >= 2 && t[0] == "p" && nostr.IsValid32ByteHex(t[1]) && !seen[t[1]] {
			seen[t[1]] = true
			out = append(out, t[1])
		}
	}
	return out, nil
}

// eventRef is a parsed reference to an event.
type eventRef struct {
	ID     string   // hex
	Relays []string // hints from nevent, if any
}

// parseEventRef accepts a 64-char hex ID, note1…, nevent1…, or any of those
// prefixed with "nostr:".
func parseEventRef(s string) (eventRef, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "nostr:")
	if lower := strings.ToLower(s); nostr.IsValid32ByteHex(lower) {
		return eventRef{ID: lower}, nil
	}
	prefix, data, err := nip19.Decode(s)
	if err != nil {
		return eventRef{}, fmt.Errorf("%q is not an event ID (expected hex, note1… or nevent1…)", s)
	}
	switch prefix {
	case "note":
		if id, ok := data.(string); ok {
			return eventRef{ID: id}, nil
		}
	case "nevent":
		if ptr, ok := data.(nostr.EventPointer); ok {
			return eventRef{ID: ptr.ID, Relays: ptr.Relays}, nil
		}
	}
	return eventRef{}, fmt.Errorf("%q is a %s, not an event ID", s, prefix)
}

// hashtagTags returns NIP-24 "t" tags for #hashtags in content: lowercase,
// trailing punctuation trimmed, de-duplicated. A bare "#" is ignored (it
// used to produce an empty tag).
func hashtagTags(content string) nostr.Tags {
	var tags nostr.Tags
	seen := map[string]bool{}
	for _, word := range strings.Fields(content) {
		if !strings.HasPrefix(word, "#") {
			continue
		}
		tag := strings.ToLower(strings.TrimRightFunc(strings.TrimLeft(word, "#"), func(r rune) bool {
			return unicode.IsPunct(r) && r != '_' && r != '-'
		}))
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true
		tags = append(tags, nostr.Tag{"t", tag})
	}
	return tags
}

// postAuthor is the author's name if known, else a short hex prefix (CLI
// output).
func postAuthor(p tui.FeedPost) string {
	if p.AuthorName != "" {
		return p.AuthorName
	}
	return shortKey(p.Author)
}
