package nip46

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
)

// Session represents an active NIP-46 connection.
type Session struct {
	ClientPrivateKey string
	ClientPublicKey  string
	SignerPublicKey  string
	RelayURLs        []string
	UserPublicKey    string

	relays []*nostr.Relay
	merged chan *nostr.Event // merged subscription events from all relays
	cancel context.CancelFunc
}

type Request struct {
	ID     string        `json:"id"`
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}

type Response struct {
	ID     string `json:"id"`
	Result string `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

// GenerateConnectURI creates a nostrconnect:// URI for QR code display.
func GenerateConnectURI(relayURLs []string, appName string) (uri string, session *Session, err error) {
	clientSK := nostr.GeneratePrivateKey()
	clientPK, err := nostr.GetPublicKey(clientSK)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get public key: %w", err)
	}

	relays := dedupStrings(relayURLs)
	if len(relays) == 0 {
		relays = []string{"wss://relay.damus.io"}
	}

	session = &Session{
		ClientPrivateKey: clientSK,
		ClientPublicKey:  clientPK,
		RelayURLs:        relays,
	}

	metadata := map[string]string{"name": appName}
	metadataJSON, _ := json.Marshal(metadata)

	q := url.Values{}
	for _, r := range relays {
		q.Add("relay", r)
	}
	q.Add("metadata", string(metadataJSON))

	uri = "nostrconnect://" + clientPK + "?" + q.Encode()
	return uri, session, nil
}

func dedupStrings(ss []string) []string {
	seen := make(map[string]struct{}, len(ss))
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

// ConnectRelays dials every configured relay in parallel and
// subscribes for NIP-46 kind 24133 events addressed to our client
// pubkey. Call this from OnInitQR (while generating the QR) so
// that by the time the user scans, the subscriptions are already
// active. Errors on individual relays are skipped; only a total
// failure (zero relays connected) returns an error.
func (s *Session) ConnectRelays(ctx context.Context) error {
	const dialTimeout = 10 * time.Second

	// Dial
	s.relays = s.dialRelays(ctx, dialTimeout)
	if len(s.relays) == 0 {
		return fmt.Errorf("could not connect to any relay (tried: %s)",
			strings.Join(s.RelayURLs, ", "))
	}

	// Subscribe on every connected relay; merge event channels.
	subCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	filter := nostr.Filter{
		Kinds: []int{24133},
		Tags:  nostr.TagMap{"p": []string{s.ClientPublicKey}},
	}

	type relaySub struct {
		events chan *nostr.Event
		close  func()
	}
	var subs []*relaySub
	for _, relay := range s.relays {
		sub, err := relay.Subscribe(subCtx, nostr.Filters{filter})
		if err != nil {
			continue
		}
		subs = append(subs, &relaySub{events: sub.Events, close: sub.Close})
	}
	if len(subs) == 0 {
		cancel()
		s.Close()
		return fmt.Errorf("no relay accepted our subscription")
	}

	// Merge into s.merged so CheckConnection can poll it.
	s.merged = make(chan *nostr.Event, 64)
	var wg sync.WaitGroup
	for _, rs := range subs {
		wg.Add(1)
		go func(rs *relaySub) {
			defer wg.Done()
			for ev := range rs.events {
				select {
				case s.merged <- ev:
				case <-subCtx.Done():
					return
				}
			}
		}(rs)
	}
	// Background cleanup: when subCtx is cancelled the forwarders
	// exit and we close merged.
	go func() {
		wg.Wait()
		close(s.merged)
	}()

	return nil
}

// CheckConnection polls for a signer connect event with a short
// timeout. Returns the signer's pubkey on success, or an error if
// nothing arrived yet. Callers should retry until success or a
// hard timeout. This is meant to be called from the TUI's
// OnCheckQR in a polling loop.
func (s *Session) CheckConnection(timeout time.Duration) (string, error) {
	if s.merged == nil {
		return "", fmt.Errorf("not connected — call ConnectRelays first")
	}

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	for {
		select {
		case ev, ok := <-s.merged:
			if !ok {
				return "", fmt.Errorf("subscription closed")
			}
			if ev == nil {
				continue
			}
			// Decrypt the content
			sharedSecret, err := nip04.ComputeSharedSecret(ev.PubKey, s.ClientPrivateKey)
			if err != nil {
				continue
			}
			decrypted, err := nip04.Decrypt(ev.Content, sharedSecret)
			if err != nil {
				continue
			}

			// Parse response
			var resp Response
			if err := json.Unmarshal([]byte(decrypted), &resp); err != nil {
				// Treat any decryptable event as connect ack.
				s.SignerPublicKey = ev.PubKey
				return ev.PubKey, nil
			}
			if resp.Result != "" || resp.Error == "" {
				s.SignerPublicKey = ev.PubKey
				return ev.PubKey, nil
			}

		case <-timer.C:
			return "", fmt.Errorf("no response yet")
		}
	}
}

func (s *Session) dialRelays(ctx context.Context, perRelayTimeout time.Duration) []*nostr.Relay {
	type result struct {
		relay *nostr.Relay
		err   error
	}
	results := make(chan result, len(s.RelayURLs))
	var wg sync.WaitGroup
	for _, u := range s.RelayURLs {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			dialCtx, cancel := context.WithTimeout(ctx, perRelayTimeout)
			defer cancel()
			relay, err := nostr.RelayConnect(dialCtx, u)
			results <- result{relay: relay, err: err}
		}(u)
	}
	wg.Wait()
	close(results)

	var connected []*nostr.Relay
	for r := range results {
		if r.err == nil && r.relay != nil {
			connected = append(connected, r.relay)
		}
	}
	return connected
}

// GetPublicKey requests the user's public key from the signer.
func (s *Session) GetPublicKey(ctx context.Context) (string, error) {
	req := Request{
		ID:     fmt.Sprintf("%d", time.Now().UnixNano()),
		Method: "get_public_key",
		Params: []interface{}{},
	}

	resp, err := s.sendRequest(ctx, req)
	if err != nil {
		return "", err
	}
	if resp.Error != "" {
		return "", fmt.Errorf("signer error: %s", resp.Error)
	}

	s.UserPublicKey = resp.Result
	return resp.Result, nil
}

// SignEvent requests the signer to sign an event
func (s *Session) SignEvent(ctx context.Context, event *nostr.Event) error {
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return err
	}

	req := Request{
		ID:     fmt.Sprintf("%d", time.Now().UnixNano()),
		Method: "sign_event",
		Params: []interface{}{string(eventJSON)},
	}

	resp, err := s.sendRequest(ctx, req)
	if err != nil {
		return err
	}
	if resp.Error != "" {
		return fmt.Errorf("signer error: %s", resp.Error)
	}

	var signedEvent nostr.Event
	if err := json.Unmarshal([]byte(resp.Result), &signedEvent); err != nil {
		return fmt.Errorf("failed to parse signed event: %w", err)
	}

	event.ID = signedEvent.ID
	event.Sig = signedEvent.Sig
	return nil
}

func (s *Session) sendRequest(ctx context.Context, req Request) (*Response, error) {
	if s.SignerPublicKey == "" {
		return nil, fmt.Errorf("not connected to signer")
	}

	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := nip04.ComputeSharedSecret(s.SignerPublicKey, s.ClientPrivateKey)
	if err != nil {
		return nil, err
	}
	encrypted, err := nip04.Encrypt(string(reqJSON), sharedSecret)
	if err != nil {
		return nil, err
	}

	now := nostr.Timestamp(time.Now().Unix())
	event := nostr.Event{
		PubKey:    s.ClientPublicKey,
		CreatedAt: now,
		Kind:      24133,
		Tags:      nostr.Tags{{"p", s.SignerPublicKey}},
		Content:   encrypted,
	}
	event.Sign(s.ClientPrivateKey)

	// Publish to every connected relay.
	if err := s.publishToAllRelays(ctx, &event); err != nil {
		return nil, fmt.Errorf("failed to publish request: %w", err)
	}

	// Subscribe on every relay for the response.
	filter := nostr.Filter{
		Kinds:   []int{24133},
		Authors: []string{s.SignerPublicKey},
		Tags:    nostr.TagMap{"p": []string{s.ClientPublicKey}},
		Since:   &now,
	}

	type relaySub struct {
		events chan *nostr.Event
		close  func()
	}
	var subs []*relaySub
	for _, relay := range s.relays {
		sub, err := relay.Subscribe(ctx, nostr.Filters{filter})
		if err != nil {
			continue
		}
		subs = append(subs, &relaySub{events: sub.Events, close: sub.Close})
	}
	if len(subs) == 0 {
		return nil, fmt.Errorf("no relay accepted subscription for response")
	}

	merged := make(chan *nostr.Event, 64)
	var wg sync.WaitGroup
	for _, rs := range subs {
		wg.Add(1)
		go func(rs *relaySub) {
			defer wg.Done()
			for ev := range rs.events {
				select {
				case merged <- ev:
				case <-ctx.Done():
					return
				}
			}
		}(rs)
	}
	closeSubs := func() {
		for _, rs := range subs {
			rs.close()
		}
		go func() { wg.Wait(); close(merged) }()
	}
	defer closeSubs()

	timeout := time.After(30 * time.Second)
	for {
		select {
		case ev := <-merged:
			if ev == nil {
				continue
			}
			decrypted, err := nip04.Decrypt(ev.Content, sharedSecret)
			if err != nil {
				continue
			}
			var resp Response
			if err := json.Unmarshal([]byte(decrypted), &resp); err != nil {
				continue
			}
			if resp.ID == req.ID || strings.HasPrefix(resp.Result, "{") || resp.Error != "" {
				return &resp, nil
			}

		case <-timeout:
			return nil, fmt.Errorf("request timeout")
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (s *Session) publishToAllRelays(ctx context.Context, event *nostr.Event) error {
	if len(s.relays) == 0 {
		return fmt.Errorf("no relay connections available")
	}
	errCh := make(chan error, len(s.relays))
	var wg sync.WaitGroup
	for _, relay := range s.relays {
		wg.Add(1)
		go func(relay *nostr.Relay) {
			defer wg.Done()
			errCh <- relay.Publish(ctx, *event)
		}(relay)
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// Close closes every relay connection.
func (s *Session) Close() {
	if s.cancel != nil {
		s.cancel()
	}
	for _, r := range s.relays {
		if r != nil {
			r.Close()
		}
	}
	s.relays = nil
}
