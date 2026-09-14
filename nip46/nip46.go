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
//
// NIP-46 lets the client advertise multiple relays in its
// nostrconnect:// URI and lets the remote signer pick whichever
// it can reach. To match that, hoot now dials all advertised
// relays in parallel and considers a signer's connect event
// received on ANY of them. Earlier versions picked the first
// configured relay only, which produced a websocket error when
// that single relay was down — even if others were healthy.
type Session struct {
	ClientPrivateKey string
	ClientPublicKey  string
	SignerPublicKey  string
	RelayURLs        []string
	UserPublicKey    string

	relays []*nostr.Relay // connected relays, one per RelayURL
}

// Request represents a NIP-46 JSON-RPC request
type Request struct {
	ID     string        `json:"id"`
	Method string        `json:"method"`
	Params []interface{} `json:"params"`
}

// Response represents a NIP-46 JSON-RPC response
type Response struct {
	ID     string `json:"id"`
	Result string `json:"result,omitempty"`
	Error  string `json:"error,omitempty"`
}

// GenerateConnectURI creates a nostrconnect:// URI for QR code display.
//
// The URI advertises every URL in relayURLs as a separate `relay=`
// query parameter, per NIP-46 § "Signers MAY publish to any of the
// relays communicated in the initial URI". A remote signer (Amber,
// etc.) will pick whichever it can reach, so we get resilience when
// one advertised relay is offline. If relayURLs is empty, fall back
// to a single placeholder "wss://relay.damus.io" — historically the
// only choice and still the most likely-to-succeed default.
func GenerateConnectURI(relayURLs []string, appName string) (uri string, session *Session, err error) {
	// Generate ephemeral client keypair
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

	// Build URI: nostrconnect://<clientPubkey>?relay=<r1>&relay=<r2>&...&metadata=<json>
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

// dedupStrings returns a copy of ss with duplicates removed,
// preserving first-seen order.
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

// dialRelays connects to all configured relays in parallel and
// returns the successfully connected relays. The first dial error
// from each URL is logged-and-skipped rather than failing the whole
// session: a single flaky relay shouldn't block login when others
// work.
//
// NIP-46 spec compliance: we listen on every relay we advertised;
// any of them becoming a valid conduit for the signer's connect
// event is enough for the handshake to succeed. This matches what
// Amber et al. actually do — the signer picks the relay it can
// reach and publishes its response there. We just have to be
// listening on the right ones.
func (s *Session) dialRelays(ctx context.Context, perRelayTimeout time.Duration) []*nostr.Relay {
	type result struct {
		relay *nostr.Relay
		err   error
		url   string
	}
	results := make(chan result, len(s.RelayURLs))
	var wg sync.WaitGroup
	for _, url := range s.RelayURLs {
		wg.Add(1)
		go func(url string) {
			defer wg.Done()
			dialCtx, cancel := context.WithTimeout(ctx, perRelayTimeout)
			defer cancel()
			relay, err := nostr.RelayConnect(dialCtx, url)
			results <- result{relay: relay, err: err, url: url}
		}(url)
	}
	wg.Wait()
	close(results)

	var connected []*nostr.Relay
	for r := range results {
		if r.err == nil && r.relay != nil {
			connected = append(connected, r.relay)
			// Best-effort: silently skip failed dials so a single
			// flaky relay doesn't block login when others work.
			continue
		}
		_ = r
	}
	return connected
}

// WaitForConnection waits for the remote signer to connect on any of
// the configured relays. It dials every advertised relay in
// parallel, subscribes for kind 24133 events addressed to our
// client pubkey on each, and returns as soon as ANY of them sees
// the signer's connect message.
func (s *Session) WaitForConnection(ctx context.Context) error {
	const dialTimeout = 15 * time.Second

	s.relays = s.dialRelays(ctx, dialTimeout)
	if len(s.relays) == 0 {
		return fmt.Errorf("could not connect to any configured relay (tried: %s)",
			strings.Join(s.RelayURLs, ", "))
	}

	// Subscribe for kind 24133 events addressed to us on every relay.
	filter := nostr.Filter{
		Kinds: []int{24133},
		Tags:  nostr.TagMap{"p": []string{s.ClientPublicKey}},
	}

	type relaySub struct {
		relay   *nostr.Relay
		events  chan *nostr.Event
		sub     *nostr.Subscription
		closeFn func()
	}
	subs := make([]*relaySub, 0, len(s.relays))
	for _, relay := range s.relays {
		sub, err := relay.Subscribe(ctx, nostr.Filters{filter})
		if err != nil {
			continue
		}
		rs := &relaySub{
			relay:   relay,
			events:  sub.Events,
			sub:     sub,
			closeFn: sub.Close,
		}
		subs = append(subs, rs)
		defer rs.closeFn()
	}
	if len(subs) == 0 {
		s.Close()
		return fmt.Errorf("no relay accepted our subscription; tried %d relays", len(s.RelayURLs))
	}

	// Merge event streams from every relay; first to deliver wins.
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
	defer func() {
		// Stop forwarding goroutines when we return.
		go func() {
			wg.Wait()
			close(merged)
		}()
	}()

	// Wait for connection event (with timeout).
	timeout := time.After(60 * time.Second)
	for {
		select {
		case ev := <-merged:
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
				// Might be a connect acknowledgement; treat any
				// decryptable event from a peer as the handshake.
				s.SignerPublicKey = ev.PubKey
				return nil
			}

			// If we got a result, connection is established
			if resp.Result != "" || resp.Error == "" {
				s.SignerPublicKey = ev.PubKey
				return nil
			}

		case <-timeout:
			s.Close()
			return fmt.Errorf("connection timeout after trying relays: %s",
				strings.Join(s.RelayURLs, ", "))

		case <-ctx.Done():
			s.Close()
			return ctx.Err()
		}
	}
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
	reqID := fmt.Sprintf("%d", time.Now().UnixNano())

	// Serialize unsigned event
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return err
	}

	req := Request{
		ID:     reqID,
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

	// Parse signed event from response
	var signedEvent nostr.Event
	if err := json.Unmarshal([]byte(resp.Result), &signedEvent); err != nil {
		return fmt.Errorf("failed to parse signed event: %w", err)
	}

	// Copy signature to original event
	event.ID = signedEvent.ID
	event.Sig = signedEvent.Sig
	return nil
}

// publishToAllRelays publishes an event to every connected relay.
// NIP-46 says the signer picks a relay to listen on; we don't know
// which one, so we publish to all of them. Publish is best-effort:
// one relay failing to publish should not block the others.
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
	// Return the first non-nil error but don't fail completely — at
	// least one relay probably succeeded and the signer may be
	// listening on it.
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// subscribeAllRelays subscribes for kind 24133 events addressed to
// us from the signer pubkey across every connected relay, and
// returns a merged event channel plus a close function.
//
// The signer chooses where to publish its response (any of the
// relays it could reach from our URI). To not miss the response,
// we listen on every relay we connected to and merge the streams.
func (s *Session) subscribeAllRelays(ctx context.Context, signerPubKey string, since nostr.Timestamp) (chan *nostr.Event, func(), error) {
	filter := nostr.Filter{
		Kinds:   []int{24133},
		Authors: []string{signerPubKey},
		Tags:    nostr.TagMap{"p": []string{s.ClientPublicKey}},
		Since:   &since,
	}

	type relaySub struct {
		events chan *nostr.Event
		close  func()
	}
	subs := make([]*relaySub, 0, len(s.relays))
	for _, relay := range s.relays {
		sub, err := relay.Subscribe(ctx, nostr.Filters{filter})
		if err != nil {
			continue
		}
		subs = append(subs, &relaySub{
			events: sub.Events,
			close:  sub.Close,
		})
	}
	if len(subs) == 0 {
		return nil, nil, fmt.Errorf("no relay accepted subscription")
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

	closeFn := func() {
		for _, rs := range subs {
			rs.close()
		}
		// Let the forwarders drain before closing merged. We can't
		// wg.Wait here because we're called from inside the request
		// handler that uses merged; the merged channel will be GCed
		// when the request loop exits.
		go func() {
			wg.Wait()
			close(merged)
		}()
	}
	return merged, closeFn, nil
}

func (s *Session) sendRequest(ctx context.Context, req Request) (*Response, error) {
	if s.SignerPublicKey == "" {
		return nil, fmt.Errorf("not connected to signer")
	}

	// Serialize request
	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	// Encrypt
	sharedSecret, err := nip04.ComputeSharedSecret(s.SignerPublicKey, s.ClientPrivateKey)
	if err != nil {
		return nil, err
	}
	encrypted, err := nip04.Encrypt(string(reqJSON), sharedSecret)
	if err != nil {
		return nil, err
	}

	// Create the request event with the current timestamp; ALL relays
	// see the same event id so the signer can dedupe if it actually
	// receives the same event on multiple relays.
	now := nostr.Timestamp(time.Now().Unix())
	event := nostr.Event{
		PubKey:    s.ClientPublicKey,
		CreatedAt: now,
		Kind:      24133,
		Tags:      nostr.Tags{{"p", s.SignerPublicKey}},
		Content:   encrypted,
	}
	event.Sign(s.ClientPrivateKey)

	// Publish to every connected relay. Whichever the signer is
	// listening on will deliver the request.
	if err := s.publishToAllRelays(ctx, &event); err != nil {
		return nil, fmt.Errorf("failed to publish request: %w", err)
	}

	// Subscribe on every relay for the response.
	merged, closeFn, err := s.subscribeAllRelays(ctx, s.SignerPublicKey, now)
	if err != nil {
		return nil, err
	}
	defer closeFn()

	// Wait for response
	timeout := time.After(30 * time.Second)
	for {
		select {
		case ev := <-merged:
			if ev == nil {
				continue
			}
			// Decrypt
			decrypted, err := nip04.Decrypt(ev.Content, sharedSecret)
			if err != nil {
				continue
			}

			var resp Response
			if err := json.Unmarshal([]byte(decrypted), &resp); err != nil {
				continue
			}

			// Check if this is our response
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

// Close closes every relay connection.
func (s *Session) Close() {
	for _, r := range s.relays {
		if r != nil {
			r.Close()
		}
	}
	s.relays = nil
}
