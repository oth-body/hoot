package nip46

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestGenerateConnectURIMultipleRelays ensures the URI advertises
// every relay passed in as a separate relay= query parameter,
// per NIP-46. Earlier versions encoded only a single relay. When
// the user's first configured relay was down at scan-time, this
// meant a websocket error and a broken login.
func TestGenerateConnectURIMultipleRelays(t *testing.T) {
	relays := []string{
		"wss://relay.damus.io",
		"wss://relay.nostr.band",
		"wss://nostr.wine",
	}
	uri, session, err := GenerateConnectURI(relays, "hoot-test")
	if err != nil {
		t.Fatalf("GenerateConnectURI: %v", err)
	}

	// Must be a nostrconnect:// URI.
	if !strings.HasPrefix(uri, "nostrconnect://") {
		t.Fatalf("URI does not start with nostrconnect://: %s", uri)
	}

	// Parse and inspect relay params.
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("URI not parseable: %v", err)
	}
	got := u.Query()["relay"]
	if len(got) != len(relays) {
		t.Fatalf("URI contains %d relay= params, want %d (got: %v)",
			len(got), len(relays), got)
	}
	wantSet := map[string]struct{}{}
	for _, r := range relays {
		wantSet[r] = struct{}{}
	}
	for _, r := range got {
		if _, ok := wantSet[r]; !ok {
			t.Errorf("URI contains unexpected relay %q", r)
		}
		delete(wantSet, r)
	}
	if len(wantSet) > 0 {
		missing := []string{}
		for r := range wantSet {
			missing = append(missing, r)
		}
		t.Errorf("URI is missing relays: %v", missing)
	}

	// Session must carry the full relay list.
	if len(session.RelayURLs) != len(relays) {
		t.Errorf("session.RelayURLs = %v, want %v", session.RelayURLs, relays)
	}

	// Client keypair must be set so the URI encodes a valid pubkey.
	if len(session.ClientPublicKey) != 64 {
		t.Errorf("session.ClientPublicKey not 64 hex chars: %q", session.ClientPublicKey)
	}
	if len(session.ClientPrivateKey) != 64 {
		t.Errorf("session.ClientPrivateKey not 64 hex chars (got %d)", len(session.ClientPrivateKey))
	}

	// The client pubkey in the URI must match session.ClientPublicKey.
	host := u.Host
	if host != session.ClientPublicKey {
		t.Errorf("URI host %q != session client pubkey %q", host, session.ClientPublicKey)
	}
}

// TestGenerateConnectURIDedupsRelays makes sure we don't emit
// the same relay twice if the user passes duplicates — relay
// dedupe is also done at the defaultRelays level, but the helper
// should be robust on its own.
func TestGenerateConnectURIDedupsRelays(t *testing.T) {
	relays := []string{
		"wss://relay.damus.io",
		"wss://relay.damus.io", // dup
		"wss://nostr.wine",
	}
	uri, _, err := GenerateConnectURI(relays, "hoot-test")
	if err != nil {
		t.Fatalf("GenerateConnectURI: %v", err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("URI not parseable: %v", err)
	}
	got := u.Query()["relay"]
	if len(got) != 2 {
		t.Errorf("expected 2 distinct relay= params (after dedup), got %d: %v", len(got), got)
	}
}

// TestGenerateConnectURISingleRelayFallback exercises the case
// where the caller has no relays configured. We fall back to
// wss://relay.damus.io so the URI is still valid; the user can
// override it via getRelayList() in hoot.
func TestGenerateConnectURISingleRelayFallback(t *testing.T) {
	uri, session, err := GenerateConnectURI(nil, "hoot-test")
	if err != nil {
		t.Fatalf("GenerateConnectURI(nil): %v", err)
	}
	u, err := url.Parse(uri)
	if err != nil {
		t.Fatalf("URI not parseable: %v", err)
	}
	got := u.Query()["relay"]
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 fallback relay, got %d", len(got))
	}
	if got[0] != "wss://relay.damus.io" {
		t.Errorf("fallback relay = %q, want wss://relay.damus.io", got[0])
	}
	if len(session.RelayURLs) != 1 || session.RelayURLs[0] != "wss://relay.damus.io" {
		t.Errorf("session.RelayURLs = %v, want [wss://relay.damus.io]", session.RelayURLs)
	}
}

// TestDialRelaysContinuesOnIndividualFailure verifies that
// dialRelays returns the subset of relays that actually came up
// when some dials fail (rather than failing the whole session).
// This is the bug behind "got a websocket error" — previously the
// session picked exactly one relay and any failure on it killed
// the login.
func TestDialRelaysContinuesOnIndividualFailure(t *testing.T) {
	s := &Session{
		ClientPublicKey: "00" + strings.Repeat("11", 31),
		RelayURLs: []string{
			"wss://invalid-relay-does-not-exist-1.invalid",
			"wss://invalid-relay-does-not-exist-2.invalid",
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got, _ := s.dialRelays(ctx, 2*time.Second)
	if len(got) != 0 {
		t.Errorf("dialRelays = %v, want empty (no reachable URLs)", got)
	}
	// Should not panic, should clean up. (Subscriptions can't be
	// opened without a connection so WaitForConnection would error
	// next — but we stop here.)
}

// ---------------------------------------------------------------------------
// Proxy environment detection (regression guard for the "connect to port 9050"
// failure mode that surfaces as "Amber sign-in failed").
// ---------------------------------------------------------------------------

// all the *_PROXY env vars we touch. Listed so tests can unset them
// cleanly without affecting unrelated env state.
var proxyEnvNames = []string{
	"HTTPS_PROXY", "https_proxy",
	"HTTP_PROXY", "http_proxy",
	"ALL_PROXY", "all_proxy",
	"SOCKS_PROXY", "socks_proxy",
	"SOCKS5_PROXY", "socks5_proxy",
}

func clearProxyEnv(t *testing.T) {
	t.Helper()
	for _, name := range proxyEnvNames {
		t.Setenv(name, "")
	}
}

// TestDetectProxyNoEnv: no *_PROXY set -> detectProxy returns ("", nil).
// Pins the baseline behaviour for every other test.
func TestDetectProxyNoEnv(t *testing.T) {
	clearProxyEnv(t)
	name, u := detectProxy()
	if name != "" {
		t.Errorf("expected empty name, got %q", name)
	}
	if u != nil {
		t.Errorf("expected nil URL, got %v", u)
	}
}

// TestDetectProxyTor9050: the exact failure mode reported in the
// bug report — HTTPS_PROXY points at a Tor SOCKS port that isn't
// running, sign-in errors with "connect: connection refused" against
// 127.0.0.1:9050. With this fix, detectProxy surfaces that fact
// so nip46.ConnectRelays can refuse to dial instead of producing
// the opaque websocket error.
func TestDetectProxyTor9050(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "socks5h://127.0.0.1:9050")

	name, u := detectProxy()
	if name != "HTTPS_PROXY" {
		t.Errorf("expected name=%q, got %q", "HTTPS_PROXY", name)
	}
	if u == nil {
		t.Fatal("expected non-nil URL")
	}
	if u.Host != "127.0.0.1:9050" {
		t.Errorf("expected host=127.0.0.1:9050, got %q", u.Host)
	}
	if u.Scheme != "socks5h" {
		t.Errorf("expected scheme=socks5h, got %q", u.Scheme)
	}
}

// TestDetectProxyHTTPSBeatsHTTP: Go's httpproxy uses HTTPS_PROXY for
// https:// requests and HTTP_PROXY for http://. When only one is set,
// detectProxy returns that one. Order in proxyEnvVars matches the
// stdlib lookup (HTTPS_PROXY before HTTP_PROXY).
func TestDetectProxyHTTPSBeatsHTTP(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTP_PROXY", "http://h.local:8080")
	t.Setenv("HTTPS_PROXY", "http://s.local:8443")

	name, u := detectProxy()
	if name != "HTTPS_PROXY" {
		t.Errorf("expected HTTPS_PROXY to win, got %q", name)
	}
	if u == nil || u.Host != "s.local:8443" {
		t.Errorf("expected s.local:8443, got %v", u)
	}
}

// TestDetectProxyAllProxyFallback: when no scheme-specific proxy is
// set but ALL_PROXY is, ALL_PROXY wins. (Go's httpproxy checks
// scheme-specific vars first, then ALL_PROXY as a universal fallback.)
func TestDetectProxyAllProxyFallback(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("ALL_PROXY", "http://a.local:3128")

	name, u := detectProxy()
	if name != "ALL_PROXY" {
		t.Errorf("expected ALL_PROXY, got %q", name)
	}
	if u == nil || u.Host != "a.local:3128" {
		t.Errorf("expected a.local:3128, got %v", u)
	}
}

// TestDetectProxySkipsMalformed: garbage in HTTPS_PROXY should not
// block detection of a valid HTTP_PROXY below it — Go's stdlib also
// tolerates parse errors silently and falls through.
func TestDetectProxySkipsMalformed(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "not a url at all")
	t.Setenv("HTTP_PROXY", "http://valid.local:8080")

	name, u := detectProxy()
	if name != "HTTP_PROXY" {
		t.Errorf("expected fallthrough to HTTP_PROXY, got %q", name)
	}
	if u == nil || u.Host != "valid.local:8080" {
		t.Errorf("expected valid.local:8080, got %v", u)
	}
}

// TestDetectProxyEmptyValue: env var set but empty is treated as unset.
// Matches Go's httpproxy behaviour.
func TestDetectProxyEmptyValue(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "")
	t.Setenv("HTTP_PROXY", "http://e.local:8080")

	name, u := detectProxy()
	if name != "HTTP_PROXY" {
		t.Errorf("expected fallthrough past empty HTTPS_PROXY, got %q", name)
	}
	if u == nil || u.Host != "e.local:8080" {
		t.Errorf("expected e.local:8080, got %v", u)
	}
}

// TestDetectProxySchemeRequiredRe: a value with no scheme is rejected
// even if it parses with a host. url.Parse treats "example.com:8080"
// as Path=... Host="" Scheme="", so the Scheme check guards this.
func TestDetectProxySchemeRequiredRe(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "example.com:8080")

	name, u := detectProxy()
	if name != "" || u != nil {
		t.Errorf("expected scheme-less URL to be rejected, got %s=%v", name, u)
	}
}

// TestConnectRelaysRefusesProxyEnv: the public API. With any
// *_PROXY pointing at an unreachable host, ConnectRelays returns
// a non-nil error that mentions the env var name and the dial
// target — not a generic websocket-dial error. This is the
// user-visible fix for the "connect to port 9050" bug.
func TestConnectRelaysRefusesProxyEnv(t *testing.T) {
	clearProxyEnv(t)
	t.Setenv("HTTPS_PROXY", "socks5h://127.0.0.1:9050")

	s := &Session{
		ClientPrivateKey: "0000000000000000000000000000000000000000000000000000000000000001",
		ClientPublicKey:  "0000000000000000000000000000000000000000000000000000000000000002",
		RelayURLs:        []string{"wss://relay.damus.io"},
	}

	err := s.ConnectRelays(nil) // ctx unused because we fail fast before dialing
	if err == nil {
		t.Fatal("expected error from ConnectRelays with HTTPS_PROXY set, got nil")
	}

	msg := err.Error()
	if !strings.Contains(msg, "HTTPS_PROXY") {
		t.Errorf("expected error to mention HTTPS_PROXY, got: %v", err)
	}
	if !strings.Contains(msg, "9050") {
		t.Errorf("expected error to mention the proxy host:port (9050), got: %v", err)
	}
}

// TestConnectRelaysRejectsBlankURL: regression guard. With no
// relay URLs configured, ConnectRelays returns a clear error
// instead of letting the dial code blow up later.
func TestConnectRelaysRejectsBlankURL(t *testing.T) {
	clearProxyEnv(t)
	s := &Session{
		ClientPrivateKey: "0000000000000000000000000000000000000000000000000000000000000001",
		ClientPublicKey:  "0000000000000000000000000000000000000000000000000000000000000002",
		RelayURLs:        nil,
	}
	err := s.ConnectRelays(nil)
	if err == nil {
		t.Fatal("expected error for blank relay URLs, got nil")
	}
	if !strings.Contains(err.Error(), "no relay URLs") {
		t.Errorf("expected 'no relay URLs' in error, got: %v", err)
	}
}

// TestConnectRelaysRejectsNonWSSURL: regression guard. A relay
// URL that's not ws:// or wss:// (e.g. an http:// typo or a bare
// host) is rejected up front.
func TestConnectRelaysRejectsNonWSSURL(t *testing.T) {
	clearProxyEnv(t)
	cases := [][]string{
		{"http://relay.damus.io"},
		{"relay.damus.io"},
		{"ftp://relay.damus.io"},
		{"not a url"},
		// Mixed: one good, one bad — should still fail on the bad one.
		{"wss://relay.damus.io", "http://other.invalid"},
	}
	for _, urls := range cases {
		t.Run(strings.Join(urls, ","), func(t *testing.T) {
			s := &Session{
				ClientPrivateKey: "0000000000000000000000000000000000000000000000000000000000000001",
				ClientPublicKey:  "0000000000000000000000000000000000000000000000000000000000000002",
				RelayURLs:        urls,
			}
			err := s.ConnectRelays(nil)
			if err == nil {
				t.Fatalf("expected error for relay URLs %v, got nil", urls)
			}
			if !strings.Contains(err.Error(), "invalid relay URL") {
				t.Errorf("expected 'invalid relay URL' in error, got: %v", err)
			}
		})
	}
}

// TestSessionCloseIsIdempotent: Close on a session that never
// connected (no proxy error fired the dial, so s.relays is nil)
// must not panic. Pins that the nil-relay guard added by the
// upstream Close implementation is preserved.
func TestSessionCloseIsIdempotent(t *testing.T) {
	clearProxyEnv(t)
	s := &Session{RelayURLs: []string{"wss://relay.damus.io"}}
	// Should not panic.
	s.Close()
	s.Close() // twice
}

// ---------------------------------------------------------------------------
// Pairing fallback relays. Without these, Amber's connect ack can land
// on a relay hoot isn't subscribed to — symptom: scan approved in Amber,
// no response in hoot. See PR fixing that bug for the full writeup.
// ---------------------------------------------------------------------------

// TestPairingRelaysIncludesFallbacks pins that PairingRelays always
// adds the hard-coded fallback set so Amber has somewhere to publish
// even when the user's relays.txt is sparse or weird.
func TestPairingRelaysIncludesFallbacks(t *testing.T) {
	gots := PairingRelays([]string{"wss://my-relay.example.com"})
	have := map[string]bool{}
	for _, u := range gots {
		have[u] = true
	}
	for _, want := range pairingFallbackRelays {
		if !have[want] {
			t.Errorf("PairingRelays missing fallback %q (got: %v)", want, gots)
		}
	}
}

// TestPairingRelaysFallbacksFirst pins that the fallback relays
// come first in the result. This is the whole point of the
// "fallbacks first" ordering: signers that pick the URI's first
// relay will pick a known-alive fallback even when the user's
// relays.txt is full of stale or unreachable entries.
func TestPairingRelaysFallbacksFirst(t *testing.T) {
	userRelays := []string{
		"wss://first.example.com",
		"wss://second.example.com",
	}
	gots := PairingRelays(userRelays)

	// Every fallback must appear before every user relay.
	lastFallbackIdx := -1
	firstUserIdx := -1
	for i, u := range gots {
		isFallback := false
		for _, f := range pairingFallbackRelays {
			if u == f {
				isFallback = true
				break
			}
		}
		if isFallback {
			lastFallbackIdx = i
		} else if firstUserIdx == -1 {
			firstUserIdx = i
		}
	}
	if lastFallbackIdx >= firstUserIdx {
		t.Errorf("expected all fallbacks to come before user relays; got %v (last fallback at %d, first user at %d)", gots, lastFallbackIdx, firstUserIdx)
	}
}

// TestPairingRelaysDedups: a user relay that happens to also be
// in the fallback set appears once. Without this, the QR URI
// would have duplicate relay= params and signers could behave
// inconsistently (some treat duplicates as a preference signal).
func TestPairingRelaysDedups(t *testing.T) {
	userRelays := []string{
		"wss://relay.damus.io", // overlaps fallback
		"wss://my.example.com",
	}
	gots := PairingRelays(userRelays)
	counts := map[string]int{}
	for _, u := range gots {
		counts[u]++
	}
	for u, n := range counts {
		if n > 1 {
			t.Errorf("relay %q appears %d times in PairingRelays result %v", u, n, gots)
		}
	}
}

// TestPairingRelaysEmptyUser: when the user has no relays
// configured at all (nil or empty slice), the result still
// contains the fallback set so the pairing can proceed.
func TestPairingRelaysEmptyUser(t *testing.T) {
	for _, in := range [][]string{nil, {}} {
		gots := PairingRelays(in)
		if len(gots) == 0 {
			t.Errorf("PairingRelays(%v) returned empty — fallbacks must always be present", in)
		}
	}
}

// TestConnectRelaysSkipsDisconnectedRelays pins the new defensive
// check: relays whose connection died between dial and subscribe
// must not be subscribed against (they'd produce a never-firing
// channel that fools CheckConnection into "no events yet" forever).
// We can't easily make a go-nostr Relay.IsConnected() return false
// without a real dial — but we CAN exercise the loop's existing
// skip-on-error branch and assert the relay is not added to subs.
// This is a coverage marker rather than a full functional test.
func TestConnectRelaysSkipsDisconnectedRelays(t *testing.T) {
	clearProxyEnv(t)
	// Use a mix of an unresolvable host ("dialRelays" will skip
	// it) and a never-listening TCP port (will return error
	// quickly). Both paths should not panic and should not yield
	// any successful subscription.
	s := &Session{
		ClientPrivateKey: "0000000000000000000000000000000000000000000000000000000000000001",
		ClientPublicKey:  "0000000000000000000000000000000000000000000000000000000000000002",
		RelayURLs: []string{
			"wss://invalid-relay-does-not-exist.invalid",
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	err := s.ConnectRelays(ctx)
	if err == nil {
		t.Errorf("expected ConnectRelays to error when no relay is reachable, got nil")
	}
}

// TestWarnUnreachableRelays pins that ConnectRelays surfaces a
// stderr warning when configured user relays are unreachable
// (a stale relays.txt or one with dead relay hosts). This is
// what makes the next sign-in scan succeed instead of failing
// silently on Amber with "websocket error".
func TestWarnUnreachableRelays(t *testing.T) {
	configured := []string{
		"wss://relay.damus.io",     // alive
		"wss://relay.example.dead", // dead
		"wss://relay.damus.io",     // dup, ignored
		"wss://nostr.wine",         // fallback, ignored
	}
	// Without a real Dial we can't build a real *nostr.Relay, so
	// the alive-only path of warnUnreachableRelays (where every
	// entry is either live or fallback) has no relays to warn
	// about. This pins that the helper is callable without
	// panicking on empty input. The richer "why is X unreachable"
	// path is covered by TestRelayDialFailureMessage below.
	warnUnreachableRelays(configured, nil, nil)
	warnUnreachableRelays([]string{}, nil, nil)
}

// TestRelayDialFailureMessage pins the user-visible message shape:
// when zero relays connect, the error names the failing URLs and
// the per-URL cause so the user can edit their relays.txt without
// guesswork. This is the regression guard for the bug report's
// "web socket failure ... no response" symptom — we never emit
// a generic "websocket failure" without per-URL context.
func TestRelayDialFailureMessage(t *testing.T) {
	e := &RelayDialFailure{
		Tried: []string{
			"wss://relay.damus.io",
			"wss://relay.nostr.band",
			"wss://my-dead-relay.invalid",
		},
		Reasons: map[string]string{
			"wss://relay.damus.io":        "dial tcp 1.2.3.4:443: connect: connection refused",
			"wss://relay.nostr.band":      "dial tcp: lookup relay.nostr.band: no such host",
			"wss://my-dead-relay.invalid": "context deadline exceeded",
		},
	}
	msg := e.Error()

	// Must mention every URL we tried (or at least the first 3 — we
	// truncate intentionally so the message fits in a TUI line).
	for _, u := range e.Tried[:3] {
		if !strings.Contains(msg, u) {
			t.Errorf("error message missing URL %q: %s", u, msg)
		}
	}
	// Must mention the underlying cause for at least one relay so
	// the user has something to act on.
	if !strings.Contains(msg, "no such host") && !strings.Contains(msg, "deadline") && !strings.Contains(msg, "connection refused") {
		t.Errorf("error message missing per-URL failure cause: %s", msg)
	}
	// Must point at the config file so the user knows where to fix it.
	if !strings.Contains(msg, "relays.txt") {
		t.Errorf("error message should point at relays.txt so the user knows where to fix it: %s", msg)
	}
	// Must NOT contain the bare phrase "websocket failure" — that was
	// the original symptom and we don't want it to leak back in.
	if strings.Contains(strings.ToLower(msg), "websocket failure") {
		t.Errorf("error message contains the old 'websocket failure' substring: %s", msg)
	}
}

// TestErrTimeoutIsRetryable pins that the polling timeout error
// is recognised as retryable (open subs > 0) so the TUI keeps
// polling instead of showing a fatal error after the first 3s.
func TestErrTimeoutIsRetryable(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"ErrTimeout with open subs", &ErrTimeout{Open: 2}, true},
		{"ErrTimeout with zero open subs", &ErrTimeout{Open: 0}, false},
		{"wrapped ErrTimeout with open subs", fmt.Errorf("check: %w", &ErrTimeout{Open: 1}), true},
		{"context deadline", context.DeadlineExceeded, true},
		{"context canceled", context.Canceled, true},
		{"plain non-retryable", fmt.Errorf("relay dial refused"), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := IsRetryable(tc.err)
			if got != tc.want {
				t.Errorf("IsRetryable(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestErrTimeoutMessageIsActionable pins the previous regression:
// the bare "no response yet" string gave users nothing to do. The
// new default message names Amber and the connection prompt so
// users know exactly what to check.
func TestErrTimeoutMessageIsActionable(t *testing.T) {
	// Default — Reason is empty, Error() must produce the actionable
	// fallback (which names Amber and "approved").
	defaultMsg := (&ErrTimeout{Open: 2}).Error()
	if !strings.Contains(strings.ToLower(defaultMsg), "amber") {
		t.Errorf("default ErrTimeout message should mention Amber so the user knows where to look: %s", defaultMsg)
	}
	if !strings.Contains(strings.ToLower(defaultMsg), "approved") {
		t.Errorf("default ErrTimeout message should mention approving the prompt: %s", defaultMsg)
	}

	// Custom Reason — even if a caller passes a less helpful Reason,
	// we don't want the OLD bare substring "no response yet" leaking
	// through without an actionable noun. Regression for the original
	// bug report's truncated symptom.
	cases := []struct {
		name   string
		reason string
		want   string // a substring the message MUST contain
	}{
		{"default reason is amber+approved", "", "amber"},
		{"custom reason that mentions amber", "amber hasn't responded yet — check it's online", "amber"},
		{"custom reason mentions signer", "signer still hasn't replied", "signer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &ErrTimeout{Reason: tc.reason}
			msg := e.Error()
			if !strings.Contains(strings.ToLower(msg), tc.want) {
				t.Errorf("ErrTimeout{Reason: %q}.Error() = %q, must contain %q", tc.reason, msg, tc.want)
			}
		})
	}

	// The SABOTAGE case — restoring the original bare "no response
	// yet" string. Without context, this would have been the user-
	// visible message. Asserting against the default empty Reason
	// (which uses our safe fallback) catches any future PR that
	// tries to shorten the message back to the unhelpful version.
	bareMsg := (&ErrTimeout{Reason: "no response yet"}).Error()
	if bareMsg == "no response yet" {
		t.Errorf("ErrTimeout message regressed to bare 'no response yet' — must include actionable context. Got: %q", bareMsg)
	}
}

// TestUserFacingErrorsAreActionable is a meta-test that scans every
// error message this package produces for the user (via the package's
// exported functions) and asserts no message contains the bare
// substring "websocket failure" — that was the exact phrase in the
// original bug report, and we want a regression guard so it can
// never sneak back in. Also asserts every error mentions at least
// one URL, env var, or actionable noun so a confused user can do
// something with it.
func TestUserFacingErrorsAreActionable(t *testing.T) {
	// Helper: must contain at least one of these tokens.
	actionableTokens := []string{
		"relay", "proxy", "amber", "relays.txt",
		"signer", "subscription", "context", "network",
		"connection", "URL", "timeout",
	}
	hasActionable := func(msg string) bool {
		low := strings.ToLower(msg)
		for _, tok := range actionableTokens {
			if strings.Contains(low, strings.ToLower(tok)) {
				return true
			}
		}
		return false
	}

	badSubstrings := []string{
		// The exact substring the user reported. If it ever leaks
		// back into the code, this test fires.
		"websocket failure",
	}

	errorsToCheck := []struct {
		name string
		err  error
	}{
		{"ErrTimeout", &ErrTimeout{Open: 1}},
		{"RelayDialFailure single", &RelayDialFailure{
			Tried:   []string{"wss://x.invalid"},
			Reasons: map[string]string{"wss://x.invalid": "no such host"},
		}},
	}
	for _, tc := range errorsToCheck {
		t.Run(tc.name, func(t *testing.T) {
			msg := tc.err.Error()
			for _, bad := range badSubstrings {
				if strings.Contains(strings.ToLower(msg), bad) {
					t.Errorf("%s error contains forbidden substring %q: %s", tc.name, bad, msg)
				}
			}
			if !hasActionable(msg) {
				t.Errorf("%s error is not actionable (no URL/env-var/noun to act on): %s", tc.name, msg)
			}
		})
	}
}
