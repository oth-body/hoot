package main

// Lightning tipping: resolve a recipient to a Lightning address (LUD-16),
// get an invoice from their LNURL-pay endpoint (LUD-06), and pay it through
// the user's wallet over Nostr Wallet Connect (NIP-47), waiting for the
// wallet's answer.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"hoot/internal/relay"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip19"
	"github.com/nbd-wtf/go-nostr/nip44"
)

// lnurlHTTPClient is used for every LNURL request. 10s matches the LUD-06
// recommendation; tests swap in an httptest TLS client.
var lnurlHTTPClient = &http.Client{Timeout: 10 * time.Second}

// nwcResponseTimeout is how long payInvoiceNWC waits for the wallet's
// kind-23195 reply. Lightning payments usually settle in seconds, but a
// wallet may hold the request while it routes.
var nwcResponseTimeout = 60 * time.Second

// ErrPaymentUnconfirmed means the wallet accepted the request over the relay
// but did not answer in time. The payment may still go through.
var ErrPaymentUnconfirmed = errors.New("wallet did not respond in time; the payment may still complete, so check your wallet before retrying")

// TipResult describes a completed tip.
type TipResult struct {
	LightningAddress string
	AmountSats       int64
	Zapped           bool   // sent as a NIP-57 zap (visible on Nostr), not a plain tip
	Preimage         string // proof of payment, from the wallet
	FeesPaidMsat     int64
}

// String renders a one-line human summary.
func (r TipResult) String() string {
	verb := "Paid"
	if r.Zapped {
		verb = "Zapped"
	}
	s := fmt.Sprintf("%s %d sats to %s", verb, r.AmountSats, r.LightningAddress)
	if r.FeesPaidMsat > 0 {
		s += fmt.Sprintf(" (fee %d msat)", r.FeesPaidMsat)
	}
	return s
}

// tipUser runs the whole flow. target is a Lightning address
// (name@domain), an npub, or a hex pubkey; for the latter two the address is
// read from the user's kind-0 profile (lud16). progress, if non-nil, gets
// short status lines for the CLI.
func tipUser(ctx context.Context, target string, amountSats int64, progress func(string)) (*TipResult, error) {
	if amountSats <= 0 {
		return nil, fmt.Errorf("amount must be a positive number of sats")
	}
	// Fail before any network work if the wallet isn't set up.
	nwc, err := loadNWC()
	if err != nil {
		return nil, err
	}
	target = strings.TrimSpace(target)
	lud16 := target
	if !strings.Contains(target, "@") {
		hexPub, err := parsePubKey(target)
		if err != nil {
			return nil, err
		}
		say(progress, "Resolving Lightning address from Nostr profile...")
		lud16, err = extractLud16(ctx, hexPub, getRelayList())
		if err != nil {
			return nil, fmt.Errorf("could not find a lightning address for that user: %w", err)
		}
	}
	return payLightningAddress(ctx, nwc, lud16, amountSats, nil, progress)
}

// zapUser sends a NIP-57 zap to recipient (hex pubkey), optionally for a
// specific event. If the recipient's Lightning address doesn't support
// Nostr zaps it falls back to a plain tip (TipResult.Zapped is false).
// The zap request is signed as the current user.
func zapUser(ctx context.Context, recipient, eventID string, amountSats int64, comment string) (*TipResult, error) {
	if amountSats <= 0 {
		return nil, fmt.Errorf("amount must be a positive number of sats")
	}
	nwc, err := loadNWC()
	if err != nil {
		return nil, err
	}
	lud16, err := extractLud16(ctx, recipient, getRelayList())
	if err != nil {
		return nil, fmt.Errorf("could not find a lightning address for that user: %w", err)
	}
	zap := &zapTarget{Recipient: recipient, EventID: eventID, Comment: comment}
	return payLightningAddress(ctx, nwc, lud16, amountSats, zap, nil)
}

// zapTarget describes a zap; nil means a plain tip.
type zapTarget struct {
	Recipient string // hex pubkey
	EventID   string // optional
	Comment   string
}

func say(progress func(string), f string, a ...any) {
	if progress != nil {
		progress(fmt.Sprintf(f, a...))
	}
}

// payLightningAddress pays amountSats to lud16 through the wallet. With zap
// set and a Lightning address that supports Nostr zaps (allowsNostr), it
// attaches a signed kind-9734 zap request so the payment shows on Nostr.
func payLightningAddress(ctx context.Context, nwc *nwcConn, lud16 string, amountSats int64, zap *zapTarget, progress func(string)) (*TipResult, error) {
	say(progress, "Found lightning address: %s", lud16)

	payReq, err := resolveLud16(ctx, lud16)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve lightning address: %w", err)
	}
	msat := amountSats * 1000
	if msat < payReq.MinSendable || (payReq.MaxSendable > 0 && msat > payReq.MaxSendable) {
		return nil, fmt.Errorf("%s accepts %d–%d sats, not %d",
			lud16, (payReq.MinSendable+999)/1000, payReq.MaxSendable/1000, amountSats)
	}

	var extra url.Values
	zapped := false
	if zap != nil && payReq.AllowsNostr && nostr.IsValid32ByteHex(payReq.NostrPubkey) {
		req, err := buildZapRequest(zap, msat)
		if err != nil {
			return nil, err
		}
		extra = url.Values{"nostr": {req}}
		zapped = true
	}

	say(progress, "Fetching invoice for %d sats...", amountSats)
	invoice, err := fetchLightningInvoice(ctx, payReq.Callback, msat, extra)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch invoice: %w", err)
	}

	say(progress, "Paying invoice via NWC...")
	res, err := payInvoiceNWC(ctx, nwc, invoice)
	if err != nil {
		return nil, err
	}
	return &TipResult{
		LightningAddress: lud16,
		AmountSats:       amountSats,
		Zapped:           zapped,
		Preimage:         res.Preimage,
		FeesPaidMsat:     res.FeesPaid,
	}, nil
}

// buildZapRequest returns a signed NIP-57 kind-9734 zap request as JSON.
// The recipient's zapper publishes the matching zap receipt (kind 9735) to
// the relays listed here once the invoice is paid.
func buildZapRequest(zap *zapTarget, msat int64) (string, error) {
	relays := nostr.Tag{"relays"}
	for i, r := range getRelayList() {
		if i == 5 {
			break
		}
		relays = append(relays, r)
	}
	ev := nostr.Event{
		Kind:      9734,
		Content:   zap.Comment,
		CreatedAt: nostr.Now(),
		Tags: nostr.Tags{
			relays,
			{"amount", fmt.Sprint(msat)},
			{"p", zap.Recipient},
		},
	}
	if zap.EventID != "" {
		ev.Tags = append(ev.Tags, nostr.Tag{"e", zap.EventID})
	}
	if err := signEvent(&ev); err != nil {
		return "", fmt.Errorf("couldn't sign the zap request: %w", err)
	}
	b, err := json.Marshal(ev)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// parsePubKey accepts an npub or a 64-char hex pubkey.
func parsePubKey(s string) (string, error) {
	if strings.HasPrefix(s, "npub") {
		_, decoded, err := nip19.Decode(s)
		if err != nil {
			return "", fmt.Errorf("invalid npub: %w", err)
		}
		hex, ok := decoded.(string)
		if !ok {
			return "", fmt.Errorf("invalid npub")
		}
		return hex, nil
	}
	if !nostr.IsValid32ByteHex(s) {
		return "", fmt.Errorf("%q is not a lightning address, npub or hex pubkey", s)
	}
	return s, nil
}

// ---------------------------------------------------------------- LNURL

// lnurlPayRequest is the LUD-06 payRequest response.
type lnurlPayRequest struct {
	Callback    string `json:"callback"`
	MinSendable int64  `json:"minSendable"` // msat
	MaxSendable int64  `json:"maxSendable"` // msat
	Tag         string `json:"tag"`
	AllowsNostr bool   `json:"allowsNostr"` // NIP-57: accepts zap requests
	NostrPubkey string `json:"nostrPubkey"` // NIP-57: key that signs zap receipts
	Status      string `json:"status"`
	Reason      string `json:"reason"`
}

// lnurlGet fetches url and decodes the JSON body into v, turning LNURL's
// {"status":"ERROR","reason":...} convention into a Go error.
func lnurlGet(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := lnurlHTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	var body json.RawMessage
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("LNURL server returned %s and no valid JSON", resp.Status)
	}
	var status struct {
		Status string `json:"status"`
		Reason string `json:"reason"`
	}
	_ = json.Unmarshal(body, &status)
	if strings.EqualFold(status.Status, "ERROR") {
		return fmt.Errorf("LNURL server error: %s", status.Reason)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("LNURL request failed: %s", resp.Status)
	}
	return json.Unmarshal(body, v)
}

// resolveLud16 turns name@domain into the LNURL-pay parameters (LUD-16).
func resolveLud16(ctx context.Context, lud16 string) (*lnurlPayRequest, error) {
	name, domain, ok := strings.Cut(strings.TrimSpace(lud16), "@")
	if !ok || name == "" || domain == "" || strings.Contains(domain, "@") {
		return nil, fmt.Errorf("invalid lightning address %q", lud16)
	}
	u := fmt.Sprintf("https://%s/.well-known/lnurlp/%s", domain, url.PathEscape(name))

	var pr lnurlPayRequest
	if err := lnurlGet(ctx, u, &pr); err != nil {
		return nil, err
	}
	if pr.Callback == "" {
		return nil, fmt.Errorf("LNURL response has no callback")
	}
	if pr.Tag != "" && pr.Tag != "payRequest" {
		return nil, fmt.Errorf("LNURL endpoint is %q, not a payRequest", pr.Tag)
	}
	return &pr, nil
}

// fetchLightningInvoice asks the LNURL callback for an invoice of exactly
// amountMsat and checks the invoice really is for that amount — a
// misbehaving server could otherwise hand back a bigger invoice and the
// wallet would pay it.
func fetchLightningInvoice(ctx context.Context, callback string, amountMsat int64, extra url.Values) (string, error) {
	cb, err := url.Parse(callback)
	if err != nil {
		return "", fmt.Errorf("invalid callback URL: %w", err)
	}
	q := cb.Query()
	q.Set("amount", fmt.Sprint(amountMsat))
	for k, vs := range extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	cb.RawQuery = q.Encode()

	var data struct {
		PR string `json:"pr"`
	}
	if err := lnurlGet(ctx, cb.String(), &data); err != nil {
		return "", err
	}
	if data.PR == "" {
		return "", fmt.Errorf("no payment request in response")
	}
	got, err := bolt11AmountMsat(data.PR)
	if err != nil {
		return "", err
	}
	if got != amountMsat {
		return "", fmt.Errorf("invoice is for %d msat but %d msat was requested; refusing to pay", got, amountMsat)
	}
	return data.PR, nil
}

// bolt11AmountMsat reads the amount from a BOLT-11 invoice's human-readable
// part (e.g. "lnbc2500u1..." → 250,000,000 msat). Only the HRP is parsed;
// the wallet does full validation before paying.
func bolt11AmountMsat(invoice string) (int64, error) {
	inv := strings.ToLower(strings.TrimSpace(invoice))
	inv = strings.TrimPrefix(inv, "lightning:")
	sep := strings.LastIndexByte(inv, '1')
	if !strings.HasPrefix(inv, "ln") || sep < 0 {
		return 0, fmt.Errorf("not a BOLT-11 invoice")
	}
	hrp := inv[2:sep]
	// Currency prefix (bc, tb, tbs, bcrt, sb) is letters; amount follows.
	i := 0
	for i < len(hrp) && hrp[i] >= 'a' && hrp[i] <= 'z' {
		i++
	}
	amount := hrp[i:]
	if amount == "" {
		return 0, fmt.Errorf("invoice has no amount")
	}

	mult := amount[len(amount)-1]
	digits := amount
	// msat per unit of the amount field, as a fraction num/den.
	num, den := big.NewInt(100_000_000_000), big.NewInt(1) // whole BTC
	switch mult {
	case 'm':
		num = big.NewInt(100_000_000)
	case 'u':
		num = big.NewInt(100_000)
	case 'n':
		num = big.NewInt(100)
	case 'p':
		num, den = big.NewInt(1), big.NewInt(10)
	default:
		if mult < '0' || mult > '9' {
			return 0, fmt.Errorf("invalid invoice amount multiplier %q", mult)
		}
	}
	if mult < '0' || mult > '9' {
		digits = amount[:len(amount)-1]
	}
	n, ok := new(big.Int).SetString(digits, 10)
	if !ok || n.Sign() <= 0 || (len(digits) > 1 && digits[0] == '0') {
		return 0, fmt.Errorf("invalid invoice amount %q", amount)
	}
	n.Mul(n, num)
	if new(big.Int).Mod(n, den).Sign() != 0 {
		return 0, fmt.Errorf("invoice amount %q is not a whole number of msat", amount)
	}
	n.Quo(n, den)
	if !n.IsInt64() {
		return 0, fmt.Errorf("invoice amount too large")
	}
	return n.Int64(), nil
}

// extractLud16 reads the lud16 field from pubKey's newest kind-0 profile.
func extractLud16(ctx context.Context, pubKey string, relays []string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	events := newestFirst(queryRelays(ctx, relays, nostr.Filter{Authors: []string{pubKey}, Kinds: []int{0}, Limit: 1}), 1)
	if len(events) == 0 {
		return "", fmt.Errorf("profile not found")
	}
	var profile struct {
		LUD16 string `json:"lud16"`
	}
	if err := json.Unmarshal([]byte(events[0].Content), &profile); err != nil {
		return "", fmt.Errorf("profile is not valid JSON: %w", err)
	}
	if profile.LUD16 == "" {
		return "", fmt.Errorf("user has no lightning address (lud16)")
	}
	return profile.LUD16, nil
}

// ---------------------------------------------------------------- NWC

// nwcConn is a parsed nostr+walletconnect:// URI.
type nwcConn struct {
	WalletPubKey string
	Relay        string
	Secret       string // client secret key (hex)
}

// parseNWCURI validates and parses a NIP-47 connection string.
func parseNWCURI(uri string) (*nwcConn, error) {
	if uri == "" {
		return nil, fmt.Errorf("NWC URI must not be empty")
	}
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("NWC URI is not a valid URL: %w", err)
	}
	if u.Scheme != "nostr+walletconnect" {
		return nil, fmt.Errorf("NWC URI scheme must be nostr+walletconnect, got %q", u.Scheme)
	}
	// Some wallets emit nostr+walletconnect:<pubkey>?... (no //), which
	// url.Parse puts in Opaque rather than Host.
	wallet := u.Hostname()
	if wallet == "" {
		wallet = u.Opaque
	}
	if wallet == "" {
		return nil, fmt.Errorf("NWC URI missing wallet pubkey in authority")
	}
	relay := u.Query().Get("relay")
	if relay == "" {
		return nil, fmt.Errorf("NWC URI missing required ?relay= parameter")
	}
	secret := u.Query().Get("secret")
	if secret == "" {
		return nil, fmt.Errorf("NWC URI missing required ?secret= parameter")
	}
	if !nostr.IsValid32ByteHex(wallet) {
		return nil, fmt.Errorf("NWC wallet pubkey is not 64-char hex")
	}
	if !nostr.IsValid32ByteHex(secret) {
		return nil, fmt.Errorf("NWC secret is not 64-char hex")
	}
	return &nwcConn{WalletPubKey: wallet, Relay: relay, Secret: secret}, nil
}

// validateNWCURI is the check `hoot -nwc` runs before saving.
func validateNWCURI(uri string) error {
	_, err := parseNWCURI(uri)
	return err
}

func nwcPath() string { return filepath.Join(getConfigDir(), "nwc.txt") }

func saveNWCURI(uri string) error {
	uri = strings.TrimSpace(uri)
	if err := validateNWCURI(uri); err != nil {
		return err
	}
	if err := os.MkdirAll(getConfigDir(), 0700); err != nil {
		return err
	}
	return os.WriteFile(nwcPath(), []byte(uri), 0600)
}

func getNWCURI() (string, error) {
	data, err := os.ReadFile(nwcPath())
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// loadNWC reads and parses the saved connection, with an actionable error
// when none is set.
func loadNWC() (*nwcConn, error) {
	uri, err := getNWCURI()
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("no wallet connected: run `hoot -nwc \"nostr+walletconnect://...\"` with the connection string from your wallet")
	}
	if err != nil {
		return nil, err
	}
	return parseNWCURI(uri)
}

// nwcPayResult is the "result" object of a pay_invoice response.
type nwcPayResult struct {
	Preimage string `json:"preimage"`
	FeesPaid int64  `json:"fees_paid"`
}

// nwcError is a NIP-47 error object.
type nwcError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *nwcError) Error() string {
	if e.Message == "" {
		return "wallet error " + e.Code
	}
	return fmt.Sprintf("wallet error %s: %s", e.Code, e.Message)
}

// payInvoiceNWC sends a pay_invoice request and waits for the wallet's
// response. The subscription for the response is opened before the request
// is published so a fast wallet can't answer before we're listening.
func payInvoiceNWC(ctx context.Context, conn *nwcConn, invoice string) (*nwcPayResult, error) {
	clientPub, err := nostr.GetPublicKey(conn.Secret)
	if err != nil {
		return nil, fmt.Errorf("invalid NWC secret: %w", err)
	}
	crypt, err := newNWCCrypt(conn)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(ctx, nwcResponseTimeout)
	defer cancel()

	rl, err := relay.Connect(ctx, conn.Relay)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NWC relay %s: %w", conn.Relay, err)
	}
	defer rl.Close()

	// NIP-47: use NIP-44 if the wallet's info event (kind 13194) says it
	// supports it; otherwise (older wallets) NIP-04.
	crypt.nip44 = walletSupportsNIP44(ctx, rl, conn.WalletPubKey)

	payload, _ := json.Marshal(map[string]any{
		"method": "pay_invoice",
		"params": map[string]any{"invoice": invoice},
	})
	content, err := crypt.encrypt(string(payload))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt request: %w", err)
	}
	req := nostr.Event{
		PubKey:    clientPub,
		CreatedAt: nostr.Now(),
		Kind:      23194,
		Tags:      nostr.Tags{{"p", conn.WalletPubKey}},
		Content:   content,
	}
	if crypt.nip44 {
		req.Tags = append(req.Tags, nostr.Tag{"encryption", "nip44_v2"})
	}
	if err := req.Sign(conn.Secret); err != nil {
		return nil, fmt.Errorf("failed to sign NWC request: %w", err)
	}

	sub, err := rl.Subscribe(ctx, nostr.Filters{{
		Kinds:   []int{23195},
		Authors: []string{conn.WalletPubKey},
		Tags:    nostr.TagMap{"e": []string{req.ID}},
	}})
	if err != nil {
		return nil, fmt.Errorf("failed to subscribe for wallet response: %w", err)
	}
	defer sub.Close()

	if err := rl.Publish(ctx, req); err != nil {
		return nil, fmt.Errorf("failed to send payment request to wallet relay: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ErrPaymentUnconfirmed
		case ev, ok := <-sub.Events:
			if !ok {
				return nil, ErrPaymentUnconfirmed
			}
			if ev.PubKey != conn.WalletPubKey {
				continue
			}
			if ok, _ := ev.CheckSignature(); !ok {
				continue
			}
			plain, err := crypt.decrypt(ev.Content)
			if err != nil {
				continue // not for us / undecryptable
			}
			var resp struct {
				ResultType string          `json:"result_type"`
				Error      *nwcError       `json:"error"`
				Result     json.RawMessage `json:"result"`
			}
			if err := json.Unmarshal([]byte(plain), &resp); err != nil {
				return nil, fmt.Errorf("wallet sent an unreadable response: %w", err)
			}
			if resp.Error != nil && resp.Error.Code != "" {
				return nil, resp.Error
			}
			var res nwcPayResult
			if len(resp.Result) > 0 {
				if err := json.Unmarshal(resp.Result, &res); err != nil {
					return nil, fmt.Errorf("wallet sent an unreadable result: %w", err)
				}
			}
			if res.Preimage == "" {
				return nil, fmt.Errorf("wallet response has no payment preimage")
			}
			return &res, nil
		}
	}
}

// nwcCrypt encrypts NWC traffic with NIP-44 or NIP-04.
type nwcCrypt struct {
	nip44 bool
	ck44  [32]byte
	ss04  []byte
}

func newNWCCrypt(conn *nwcConn) (*nwcCrypt, error) {
	ck, err := nip44.GenerateConversationKey(conn.WalletPubKey, conn.Secret)
	if err != nil {
		return nil, fmt.Errorf("invalid wallet connection keys: %w", err)
	}
	ss, err := nip04.ComputeSharedSecret(conn.WalletPubKey, conn.Secret)
	if err != nil {
		return nil, fmt.Errorf("invalid wallet connection keys: %w", err)
	}
	return &nwcCrypt{ck44: ck, ss04: ss}, nil
}

func (c *nwcCrypt) encrypt(plain string) (string, error) {
	if c.nip44 {
		return nip44.Encrypt(plain, c.ck44)
	}
	return nip04.Encrypt(plain, c.ss04)
}

// decrypt tries the negotiated scheme first, then the other one (a wallet
// may answer in either).
func (c *nwcCrypt) decrypt(ct string) (string, error) {
	first, second := func() (string, error) { return nip04.Decrypt(ct, c.ss04) }, func() (string, error) { return nip44.Decrypt(ct, c.ck44) }
	if c.nip44 {
		first, second = second, first
	}
	if p, err := first(); err == nil {
		return p, nil
	}
	return second()
}

// walletSupportsNIP44 reads the wallet's NIP-47 info event (kind 13194) and
// reports whether its "encryption" tag lists nip44_v2. No info event, or no
// tag, means NIP-04 only.
func walletSupportsNIP44(ctx context.Context, rl *relay.Relay, wallet string) bool {
	qctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ch, err := rl.QueryEvents(qctx, nostr.Filter{Kinds: []int{13194}, Authors: []string{wallet}, Limit: 1})
	if err != nil {
		return false
	}
	supported := false
	for ev := range ch {
		for _, t := range ev.Tags {
			if len(t) >= 2 && t[0] == "encryption" {
				for _, scheme := range strings.Fields(t[1]) {
					if scheme == "nip44_v2" {
						supported = true
					}
				}
			}
		}
	}
	return supported
}
