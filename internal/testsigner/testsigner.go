// Package testsigner is a NIP-46 remote signer ("bunker") for tests. It
// connects to a relay like Amber would and answers get_public_key,
// sign_event and the nip04/nip44 encrypt/decrypt methods with the user's key.
package testsigner

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"hoot/internal/relay"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// Signer is a running fake remote signer.
type Signer struct {
	PubKey     string // the signer's own key (what clients address requests to)
	UserPubKey string // the user's key it signs with

	// Delay, if set, is applied before answering each request; Reorder
	// makes the signer hold one answer and send it after the next, to test
	// that clients match responses by ID.
	Delay   time.Duration
	Reorder bool

	sk, userSK string
	conn       *relay.Relay
	cancel     context.CancelFunc

	mu      sync.Mutex
	calls   map[string]int
	pending *nostr.Event
}

// Start connects a signer for userSK to relayURL.
func Start(relayURL, userSK string) (*Signer, error) {
	s := &Signer{sk: nostr.GeneratePrivateKey(), userSK: userSK, calls: map[string]int{}}
	s.PubKey, _ = nostr.GetPublicKey(s.sk)
	s.UserPubKey, _ = nostr.GetPublicKey(userSK)

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	conn, err := relay.Connect(ctx, relayURL)
	if err != nil {
		cancel()
		return nil, err
	}
	s.conn = conn
	sub, err := conn.Subscribe(ctx, nostr.Filters{{Kinds: []int{24133}, Tags: nostr.TagMap{"p": []string{s.PubKey}}}})
	if err != nil {
		cancel()
		conn.Close()
		return nil, err
	}
	go func() {
		for ev := range sub.Events {
			go s.handle(ctx, ev)
		}
	}()
	return s, nil
}

// Close stops the signer.
func (s *Signer) Close() {
	s.cancel()
	s.conn.Close()
}

// Calls returns how many times method was called.
func (s *Signer) Calls(method string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls[method]
}

func (s *Signer) handle(ctx context.Context, ev *nostr.Event) {
	ss, err := nip04.ComputeSharedSecret(ev.PubKey, s.sk)
	if err != nil {
		return
	}
	plain, err := nip04.Decrypt(ev.Content, ss)
	if err != nil {
		return
	}
	var req struct {
		ID     string   `json:"id"`
		Method string   `json:"method"`
		Params []string `json:"params"`
	}
	if json.Unmarshal([]byte(plain), &req) != nil {
		return
	}
	s.mu.Lock()
	s.calls[req.Method]++
	s.mu.Unlock()

	result, rerr := s.answer(req.Method, req.Params)
	resp := map[string]string{"id": req.ID, "result": result}
	if rerr != nil {
		resp = map[string]string{"id": req.ID, "error": rerr.Error()}
	}
	b, _ := json.Marshal(resp)
	ct, _ := nip04.Encrypt(string(b), ss)
	out := &nostr.Event{PubKey: s.PubKey, CreatedAt: nostr.Now(), Kind: 24133, Tags: nostr.Tags{{"p", ev.PubKey}}, Content: ct}
	_ = out.Sign(s.sk)

	if s.Delay > 0 {
		time.Sleep(s.Delay)
	}
	if s.Reorder {
		s.mu.Lock()
		held := s.pending
		if held == nil {
			s.pending = out
			s.mu.Unlock()
			return // sent after the next response
		}
		s.pending = nil
		s.mu.Unlock()
		_ = s.conn.Publish(ctx, *out)
		_ = s.conn.Publish(ctx, *held)
		return
	}
	_ = s.conn.Publish(ctx, *out)
}

func (s *Signer) answer(method string, p []string) (string, error) {
	arg := func(i int) string {
		if i < len(p) {
			return p[i]
		}
		return ""
	}
	switch method {
	case "connect":
		return "ack", nil
	case "get_public_key":
		return s.UserPubKey, nil
	case "sign_event":
		var ev nostr.Event
		if err := json.Unmarshal([]byte(arg(0)), &ev); err != nil {
			return "", err
		}
		if err := ev.Sign(s.userSK); err != nil {
			return "", err
		}
		b, _ := json.Marshal(ev)
		return string(b), nil
	case "nip44_encrypt", "nip44_decrypt":
		ck, err := nip44.GenerateConversationKey(arg(0), s.userSK)
		if err != nil {
			return "", err
		}
		if method == "nip44_encrypt" {
			return nip44.Encrypt(arg(1), ck)
		}
		return nip44.Decrypt(arg(1), ck)
	case "nip04_encrypt", "nip04_decrypt":
		ss, err := nip04.ComputeSharedSecret(arg(0), s.userSK)
		if err != nil {
			return "", err
		}
		if method == "nip04_encrypt" {
			return nip04.Encrypt(arg(1), ss)
		}
		return nip04.Decrypt(arg(1), ss)
	}
	return "", fmt.Errorf("unsupported method %s", method)
}
