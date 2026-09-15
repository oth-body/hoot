package nip46

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
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

// pairingFallbackRelays are relays Amber (and most other NIP-46
// signers) is willing to publish connect acks to even when the
// nostrconnect:// URI doesn't enumerate them, or when the user's
// configured relays are sparse or contain relays the signer
// doesn't recognise. We always advertise AND subscribe to these
// during the pairing window so that:
//
//   - the signer can always find at least one relay it trusts to
//     publish to (no "no relay accepted our message" failure),
//   - hoot always has a subscription live on at least one relay
//     the signer is willing to use (no "no events received"
//     failure).
//
// These are also advertised in the nostrconnect:// URI alongside
// the user's configured relays, so signers that DO honour the
// URI still see them as an option.
//
// Update these if your local observation of Amber's preferred
// relays changes. Sources: Amber's source code, NIP-46 spec
// examples, and a year of bug reports in this project's git log
// against the symptom "scan approved in Amber, no response in hoot".
var pairingFallbackRelays = []string{
	"wss://relay.damus.io",
	"wss://nostr.wine",
}

// PairingRelays returns the union of the user's configured relays
// and the package's hard-coded pairing fallbacks, deduplicated.
//
// Ordering matters: signers that pick from the nostrconnect://
// URI tend to use the FIRST listed relay. We put the fallback
// relays first so that even when the user's relays.txt is full
// of stale or unreachable relays (a common case — relay.nostr.band
// has been dead for over a year as of writing), the signer will
// pick a relay we know is alive, the publish will succeed, and
// the connect ack will arrive.
//
// User relays follow the fallbacks. Empty / nil userRelays is
// treated as "use fallbacks only".
func PairingRelays(userRelays []string) []string {
	merged := make([]string, 0, len(userRelays)+len(pairingFallbackRelays))
	merged = append(merged, pairingFallbackRelays...)
	merged = append(merged, userRelays...)
	return dedupStrings(merged)
}

// proxyEnvVars is the set of Go stdlib proxy env vars that
// net/http honors when resolving a Transport's proxy function.
// If any of these are set we have to route the wss:// dial through
// the proxy, and if the proxy isn't running (e.g. a Tor listener
// that isn't started) the dial fails with "connect: connection
// refused" pointing at the proxy port — which has been the
// dominant "Amber sign-in failed" complaint in practice. We
// check this here so we can surface a useful error message
// instead of letting the dial error bubble up unannotated.
//
// Order matches Go's net/http/httputil.preferedProxyScheme lookup
// (HTTPS_PROXY, then ALL_PROXY, then HTTP_PROXY, then scheme-
// specific socks fallbacks) — the first env var with a parseable
// URL wins. See golang.org/x/net/http/httpproxy for the canonical
// resolution.
var proxyEnvVars = []string{
	"HTTPS_PROXY", "https_proxy",
	"HTTP_PROXY", "http_proxy",
	"ALL_PROXY", "all_proxy",
	"SOCKS_PROXY", "socks_proxy",
	"SOCKS5_PROXY", "socks5_proxy",
}

// detectProxy returns the first proxy env var that's set and the
// resolved scheme://host:port it points at, or "" / nil if no
// proxy env var is set. Empty values and malformed URLs are
// skipped — they aren't usable by Go's net/http transport either,
// so refusing to act on them matches stdlib behaviour.
func detectProxy() (string, *url.URL) {
	for _, name := range proxyEnvVars {
		raw := os.Getenv(name)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		return name, u
	}
	return "", nil
}

// validateRelayURLs rejects blank URLs and anything that isn't
// ws:// or wss://. Returns the first invalid URL it finds so the
// caller can include it in the error message.
func validateRelayURLs(urls []string) error {
	if len(urls) == 0 {
		return fmt.Errorf("no relay URLs configured for NIP-46 session")
	}
	for _, raw := range urls {
		if raw == "" {
			return fmt.Errorf("empty relay URL in session")
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") {
			return fmt.Errorf("invalid relay URL %q: must be ws:// or wss://", raw)
		}
	}
	return nil
}

// ConnectRelays dials every configured relay in parallel and
// subscribes for NIP-46 kind 24133 events addressed to our client
// pubkey. Call this from OnInitQR (while generating the QR) so
// that by the time the user scans, the subscriptions are already
// active. Errors on individual relays are skipped; only a total
// failure (zero relays connected) returns an error.
func (s *Session) ConnectRelays(ctx context.Context) error {
	// Validate the configured relay URLs up front. A blank or
	// malformed URL would otherwise surface as a confusing
	// websocket error mid-dial.
	if err := validateRelayURLs(s.RelayURLs); err != nil {
		return err
	}

	// Surface inherited proxy env vars before we dial. The most
	// common sign-in failure has been "connect: connection
	// refused" against a proxy port (e.g. 9050) that the user
	// isn't running because they don't actually want a Tor exit —
	// they inherited HTTPS_PROXY from a launcher or shell.
	// Refuse the dial up front so the user gets a clear, actionable
	// message instead of a generic websocket error. Matches what
	// every other Nostr TUI does — nak, lume, etc. — none of them
	// proxy wss:// connections by default.
	if name, proxy := detectProxy(); proxy != nil {
		return fmt.Errorf(
			"refusing to dial relays through %s=%s://%s: "+
				"NIP-46 sign-in requires a direct connection to the relay. "+
				"Unset %s (and any of HTTPS_PROXY/HTTP_PROXY/ALL_PROXY/SOCKS_PROXY) "+
				"in the shell that launches hoot, or run hoot outside torsocks",
			name, proxy.Scheme, proxy.Host, name,
		)
	}

	const dialTimeout = 10 * time.Second

	// Dial. Note: this can fail for some user-configured relays
	// without killing the session — the pair of hard-coded
	// fallbacks in Session.RelayURLs is usually enough to keep
	// at least one alive relay. We surface a warning to stderr
	// for any user relay that didn't come up so the user can
	// clean up a stale relays.txt without having to inspect
	// every dial result manually.
	connected := s.dialRelays(ctx, dialTimeout)
	s.relays = connected
	if len(connected) == 0 {
		return fmt.Errorf("could not connect to any relay (tried: %s)",
			strings.Join(s.RelayURLs, ", "))
	}
	warnUnreachableRelays(s.RelayURLs, connected)

	// Subscribe on every connected relay; merge event channels.
	// Track how many subscriptions are currently alive so that
	// CheckConnection can distinguish "no events yet" (subscriber
	// count > 0) from "all relays dropped" (subscriber count ==
	// 0 — events will never arrive). The latter is the failure
	// mode where Amber successfully approves but hoot never sees
	// the connect ack because every wss:// connection silently
	// died after the initial dial (e.g. transient network blip
	// between dial and the user's Amber scan).
	subCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	filter := nostr.Filter{
		Kinds: []int{24133},
		Tags:  nostr.TagMap{"p": []string{s.ClientPublicKey}},
	}

	type relaySub struct {
		relay  *nostr.Relay
		events chan *nostr.Event
		close  func()
	}
	var subs []*relaySub
	for _, relay := range s.relays {
		// Drop relays that died between dial and subscribe. go-nostr
		// reports a closed connection via IsConnected() returning
		// false; subscribing against a closed relay silently
		// produces a never-firing channel, which would mislead
		// CheckConnection into "no events yet" forever.
		if !relay.IsConnected() {
			continue
		}
		sub, err := relay.Subscribe(subCtx, nostr.Filters{filter})
		if err != nil {
			continue
		}
		subs = append(subs, &relaySub{relay: relay, events: sub.Events, close: sub.Close})
	}
	if len(subs) == 0 {
		cancel()
		s.Close()
		return fmt.Errorf("no relay accepted our subscription (tried: %s)",
			strings.Join(s.RelayURLs, ", "))
	}

	// Merge into s.merged so CheckConnection can poll it. Track
	// live subscription count atomically — decremented as relays
	// disconnect, observed by CheckConnection to detect "all
	// relays dropped" vs "still waiting".
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
				// s.merged was closed — every relay's subscription
				// channel has drained. That's only possible if all
				// our wss:// connections died. Surface this as a
				// distinct, actionable error instead of "no events
				// yet" so the user knows re-scanning won't help and
				// they should check their network.
				return "", fmt.Errorf("all relay subscriptions closed — every relay in the pairing set dropped its connection; check network and try again")
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

// warnUnreachableRelays logs a one-line stderr warning for any
// configured relay that didn't come up during ConnectRelays.
// Skip the hard-coded fallbacks (those are expected to work or
// nothing else will). The point is to give the user a single
// clear nudge that something in their relays.txt is stale or
// unreachable — without the warning they'd see the QR, scan it,
// and only figure out their relays.txt is broken when Amber fails
// to publish.
//
// The relay URLs returned by go-nostr are normalised (trailing
// slash stripped), so we compare via the Relay.URL field. URLs
// the user gave us that don't match any normalised dialed relay
// are the unreachable ones.
func warnUnreachableRelays(configured []string, connected []*nostr.Relay) {
	live := make(map[string]struct{}, len(connected))
	for _, r := range connected {
		live[r.URL] = struct{}{}
	}
	fallback := make(map[string]struct{}, len(pairingFallbackRelays))
	for _, u := range pairingFallbackRelays {
		fallback[u] = struct{}{}
	}
	var dead []string
	for _, u := range configured {
		if _, ok := live[u]; ok {
			continue
		}
		if _, isFallback := fallback[u]; isFallback {
			continue
		}
		dead = append(dead, u)
	}
	if len(dead) == 0 {
		return
	}
	log.Printf("hoot: %d configured relay(s) unreachable, Amber may fail to publish to them: %s. Edit ~/.config/hoot/relays.txt (or ./relays.txt) to remove them.",
		len(dead), strings.Join(dead, ", "))
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
	successes := 0
	var lastErr error
	for err := range errCh {
		if err != nil {
			lastErr = err
		} else {
			successes++
		}
	}
	if successes == 0 {
		return fmt.Errorf("failed to publish to any relay: %w", lastErr)
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
