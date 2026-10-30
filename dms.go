package main

// Direct messages: NIP-04 (legacy, kind 4) and NIP-17 (kind 14 rumors,
// sealed and gift-wrapped per NIP-59). Reading merges both; sending uses
// NIP-17. All crypto goes through the keyer, so this works with a local key
// and with Amber.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"hoot/internal/relay"
	"hoot/tui"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip17"
	"github.com/nbd-wtf/go-nostr/nip59"
)

// dmLimit caps how many DMs are shown.
const dmLimit = 50

// With a remote signer every decrypt is a round trip to the phone, so only
// the newest messages are decrypted.
const (
	remoteMax04   = 30
	remoteMaxWrap = 20
)

// dmFilters returns the two filters needed to see a user's whole NIP-04
// conversation history: messages they received (#p) and messages they sent
// (authors). (A single global {kinds:[4]} filter used to miss nearly all of
// them.)
func dmFilters(publicKey string) []nostr.Filter {
	return []nostr.Filter{
		{Kinds: []int{4}, Tags: nostr.TagMap{"p": []string{publicKey}}, Limit: dmLimit},
		{Kinds: []int{4}, Authors: []string{publicKey}, Limit: dmLimit},
	}
}

// dmRelays returns pubkey's NIP-17 inbox relays (kind 10050 "relay" tags).
func dmRelays(ctx context.Context, pubkey string) []string {
	evs := queryRelays(ctx, getRelayList(), nostr.Filter{Kinds: []int{10050}, Authors: []string{pubkey}, Limit: 1})
	if len(evs) == 0 {
		return nil
	}
	var out []string
	for _, t := range evs[0].Tags {
		if len(t) >= 2 && t[0] == "relay" && (strings.HasPrefix(t[1], "wss://") || strings.HasPrefix(t[1], "ws://")) {
			out = append(out, t[1])
		}
	}
	return out
}

// dm is one decrypted message before it is formatted for display.
type dm struct {
	id      string
	from    string // sender pubkey
	peer    string // the other party
	text    string
	at      nostr.Timestamp
	private bool // NIP-17
}

// decryptDM04 decrypts a kind-4 event that involves me. NIP-04's shared
// secret is ECDH with *the other party's* key: the author for incoming
// messages, the p-tagged recipient for my own sent ones.
func decryptDM04(ctx context.Context, k keyer, me string, ev *nostr.Event) (dm, bool) {
	var recipient string
	if p := ev.Tags.GetFirst([]string{"p"}); p != nil && len(*p) > 1 {
		recipient = (*p)[1]
	}
	var peer string
	switch {
	case ev.PubKey == me && recipient != "":
		peer = recipient
	case recipient == me:
		peer = ev.PubKey
	default:
		return dm{}, false
	}
	plain, err := k.Decrypt04(ctx, ev.Content, peer)
	if err != nil {
		return dm{}, false
	}
	return dm{id: ev.ID, from: ev.PubKey, peer: peer, text: plain, at: ev.CreatedAt}, true
}

// unwrapDM17 opens a NIP-59 gift wrap addressed to me and returns the kind-14
// message inside. The seal's signature is checked and the rumor's author is
// taken from the seal, so a sender can't be forged.
func unwrapDM17(ctx context.Context, k keyer, me string, gw *nostr.Event) (dm, bool) {
	rumor, err := nip59.GiftUnwrap(*gw, func(peer, ct string) (string, error) {
		return k.Decrypt(ctx, ct, peer)
	})
	if err != nil || rumor.Kind != 14 {
		return dm{}, false
	}
	peer := rumor.PubKey
	if rumor.PubKey == me {
		peer = ""
		for _, t := range rumor.Tags {
			if len(t) >= 2 && t[0] == "p" && t[1] != me {
				peer = t[1]
				break
			}
		}
		if peer == "" {
			return dm{}, false
		}
	}
	return dm{id: rumor.ID, from: rumor.PubKey, peer: peer, text: rumor.Content, at: rumor.CreatedAt, private: true}, true
}

// parallel runs fn over items with at most n at a time.
func parallel[T any](items []T, n int, fn func(T)) {
	sem := make(chan struct{}, n)
	var wg sync.WaitGroup
	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(it T) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(it)
		}(it)
	}
	wg.Wait()
}

// getDMs returns the signed-in user's DMs (NIP-04 and NIP-17, sent and
// received), newest first, with names.
func getDMs() ([]tui.FeedPost, error) {
	k, err := currentKeyer()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	me, _ := k.GetPublicKey(ctx)

	qctx, qcancel := context.WithTimeout(ctx, 15*time.Second)
	relays := append(getRelayList(), dmRelays(qctx, me)...)
	events := queryRelays(qctx, relays,
		append(dmFilters(me), nostr.Filter{Kinds: []int{1059}, Tags: nostr.TagMap{"p": []string{me}}, Limit: dmLimit})...)
	qcancel()

	var old, wraps []*nostr.Event
	for _, ev := range events { // newest first
		switch ev.Kind {
		case 4:
			old = append(old, ev)
		case 1059:
			wraps = append(wraps, ev)
		}
	}
	workers := 8
	if k.Remote() {
		workers = 4
		if len(old) > remoteMax04 {
			old = old[:remoteMax04]
		}
		if len(wraps) > remoteMaxWrap {
			wraps = wraps[:remoteMaxWrap]
		}
	}

	var mu sync.Mutex
	seen := map[string]bool{}
	var msgs []dm
	add := func(d dm, ok bool) {
		if !ok {
			return
		}
		mu.Lock()
		defer mu.Unlock()
		if !seen[d.id] {
			seen[d.id] = true
			msgs = append(msgs, d)
		}
	}
	parallel(old, workers, func(ev *nostr.Event) { add(decryptDM04(ctx, k, me, ev)) })
	parallel(wraps, workers, func(ev *nostr.Event) { add(unwrapDM17(ctx, k, me, ev)) })

	sort.SliceStable(msgs, func(i, j int) bool { return msgs[i].at > msgs[j].at })
	if len(msgs) > dmLimit {
		msgs = msgs[:dmLimit]
	}
	return formatDMs(me, msgs), nil
}

// formatDMs turns messages into display posts, labelled with names.
func formatDMs(me string, msgs []dm) []tui.FeedPost {
	var pks []string
	for _, m := range msgs {
		pks = append(pks, m.from, m.peer)
	}
	names := resolveNames(context.Background(), pks)
	label := func(pk string) string {
		if n := names[pk]; n != "" {
			return n
		}
		return shortKey(pk)
	}
	posts := make([]tui.FeedPost, 0, len(msgs))
	for _, m := range msgs {
		dir := "from"
		if m.from == me {
			dir = "to " + label(m.peer)
		}
		lock := ""
		if m.private {
			lock = "🔒 "
		}
		posts = append(posts, tui.FeedPost{
			ID:         m.id,
			Kind:       14,
			Author:     m.from,
			AuthorName: names[m.from],
			Peer:       m.peer,
			Content:    fmt.Sprintf("%s[DM %s]: %s", lock, dir, m.text),
			CreatedAt:  time.Unix(int64(m.at), 0).Format("Jan 2 15:04"),
		})
	}
	return posts
}

// sendDM sends a NIP-17 private message to recipient (hex pubkey): one gift
// wrap to the recipient's DM inbox relays (kind 10050; their/our general
// relays if they have none), and a copy to our own so it shows as sent.
func sendDM(recipient, text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return fmt.Errorf("message is empty")
	}
	if !nostr.IsValid32ByteHex(recipient) {
		return fmt.Errorf("invalid recipient public key")
	}
	k, err := currentKeyer()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	me, _ := k.GetPublicKey(ctx)

	toUs, toThem, err := nip17.PrepareMessage(ctx, text, nostr.Tags{}, k, recipient, nil)
	if err != nil {
		return fmt.Errorf("couldn't encrypt the message: %w", err)
	}

	theirs := dmRelays(ctx, recipient)
	if len(theirs) == 0 {
		theirs = getRelayList()
	}
	if _, _, err := relay.PublishAll(ctx, theirs, toThem); err != nil {
		return fmt.Errorf("couldn't deliver the message: %w", err)
	}
	ours := append(dmRelays(ctx, me), getRelayList()...)
	_, _, _ = relay.PublishAll(ctx, ours, toUs) // best effort: our sent copy
	return nil
}
