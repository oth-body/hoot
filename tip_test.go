package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"hoot/internal/testrelay"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip19"
)

func TestBolt11AmountMsat(t *testing.T) {
	ok := map[string]int64{
		"lnbc2500u1pvjluez":       250_000_000,
		"lnbc20m1pvjluez":         2_000_000_000,
		"lnbc210n1pvjluez":        21_000,
		"lnbc10p1pvjluez":         1,
		"lnbc1m1pvjluez":          100_000_000,
		"lnbc21pvjluez":           2 * 100_000_000_000, // 2 BTC, no multiplier
		"LNBC2500U1PVJLUEZ":       250_000_000,
		"lightning:lnbc210n1pxyz": 21_000,
		"lntb100u1pxyz":           10_000_000,
		"lnbcrt500n1pxyz":         50_000,
		"lntbs5u1pxyz":            500_000,
	}
	for inv, want := range ok {
		got, err := bolt11AmountMsat(inv)
		if err != nil || got != want {
			t.Errorf("bolt11AmountMsat(%q) = %d, %v; want %d", inv, got, err, want)
		}
	}
	for _, bad := range []string{
		"", "lnbc1pvjluez" /* no amount */, "lnbc15p1pxyz" /* 1.5 msat */, "lnbc10x1pxyz",
		"bc1qxyz", "lnbc0u1pxyz", "lnbc01u1pxyz", "lnbc99999999999999999999m1pxyz",
	} {
		if got, err := bolt11AmountMsat(bad); err == nil {
			t.Errorf("bolt11AmountMsat(%q) = %d, want error", bad, got)
		}
	}
}

// fakeInvoice builds a BOLT-11-shaped string whose HRP encodes msat (must be
// a multiple of 100). Only the HRP matters to hoot; the wallet is fake.
func fakeInvoice(msat int64) string { return fmt.Sprintf("lnbc%dn1pfakeinvoice", msat/100) }

type tipFixture struct {
	relay        *testrelay.Relay
	lnurl        *httptest.Server
	address      string // alice@host
	walletSK     string
	requests     atomic.Int32 // pay_invoice requests seen by the wallet
	lastInvoice  atomic.Value
	walletReply  func(invoice string) map[string]any // nil → don't reply
	invoiceMsat  func(requested int64) int64         // what the LNURL server bills
	minSendable  int64
	maxSendable  int64
	lnurlFailure string // non-empty → LNURL returns status ERROR
}

func newTipFixture(t *testing.T) *tipFixture {
	t.Helper()
	f := &tipFixture{
		relay:       startRelay(t), // skips under -race
		walletSK:    nostr.GeneratePrivateKey(),
		invoiceMsat: func(r int64) int64 { return r },
		minSendable: 1_000,
		maxSendable: 1_000_000_000,
		walletReply: func(string) map[string]any {
			return map[string]any{"result_type": "pay_invoice", "result": map[string]any{"preimage": strings.Repeat("ab", 32), "fees_paid": 3000}}
		},
	}
	isolate(t, f.relay.URL)

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/lnurlp/alice", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"callback": "https://" + r.Host + "/cb?user=alice", "tag": "payRequest",
			"minSendable": f.minSendable, "maxSendable": f.maxSendable, "metadata": "[]",
		})
	})
	mux.HandleFunc("/cb", func(w http.ResponseWriter, r *http.Request) {
		if f.lnurlFailure != "" {
			json.NewEncoder(w).Encode(map[string]any{"status": "ERROR", "reason": f.lnurlFailure})
			return
		}
		if r.URL.Query().Get("user") != "alice" {
			http.Error(w, "callback query lost", 400)
			return
		}
		var amt int64
		fmt.Sscan(r.URL.Query().Get("amount"), &amt)
		json.NewEncoder(w).Encode(map[string]any{"pr": fakeInvoice(f.invoiceMsat(amt)), "routes": []any{}})
	})
	f.lnurl = httptest.NewTLSServer(mux)
	t.Cleanup(f.lnurl.Close)
	f.address = "alice@" + strings.TrimPrefix(f.lnurl.URL, "https://")

	old := lnurlHTTPClient
	lnurlHTTPClient = f.lnurl.Client()
	t.Cleanup(func() { lnurlHTTPClient = old })

	// Connect hoot to the fake wallet.
	walletPK, _ := nostr.GetPublicKey(f.walletSK)
	clientSK := nostr.GeneratePrivateKey()
	uri := fmt.Sprintf("nostr+walletconnect://%s?relay=%s&secret=%s", walletPK, f.relay.URL, clientSK)
	if err := saveNWCURI(uri); err != nil {
		t.Fatal(err)
	}

	// The wallet: answer pay_invoice requests addressed to it.
	f.relay.OnEvent = func(ev *nostr.Event) {
		if ev.Kind != 23194 {
			return
		}
		if p := ev.Tags.GetFirst([]string{"p"}); p == nil || (*p)[1] != walletPK {
			return
		}
		ss, _ := nip04.ComputeSharedSecret(ev.PubKey, f.walletSK)
		plain, err := nip04.Decrypt(ev.Content, ss)
		if err != nil {
			return
		}
		var req struct {
			Method string `json:"method"`
			Params struct {
				Invoice string `json:"invoice"`
			} `json:"params"`
		}
		if json.Unmarshal([]byte(plain), &req) != nil || req.Method != "pay_invoice" {
			return
		}
		f.requests.Add(1)
		f.lastInvoice.Store(req.Params.Invoice)
		reply := f.walletReply(req.Params.Invoice)
		if reply == nil {
			return
		}
		b, _ := json.Marshal(reply)
		ct, _ := nip04.Encrypt(string(b), ss)
		resp := &nostr.Event{
			PubKey: walletPK, CreatedAt: nostr.Now(), Kind: 23195,
			Tags: nostr.Tags{{"p", ev.PubKey}, {"e", ev.ID}}, Content: ct,
		}
		_ = resp.Sign(f.walletSK)
		f.relay.Publish(resp)
	}
	return f
}

func TestE2ETipLightningAddressPaid(t *testing.T) {
	f := newTipFixture(t)
	var progress []string
	res, err := tipUser(context.Background(), f.address, 21, func(s string) { progress = append(progress, s) })
	if err != nil {
		t.Fatalf("tipUser: %v", err)
	}
	if res.AmountSats != 21 || res.Preimage != strings.Repeat("ab", 32) || res.FeesPaidMsat != 3000 {
		t.Fatalf("result = %+v", res)
	}
	if got := f.lastInvoice.Load(); got != fakeInvoice(21_000) {
		t.Fatalf("wallet was asked to pay %v", got)
	}
	if !strings.Contains(res.String(), "Paid 21 sats to "+f.address) {
		t.Errorf("summary = %q", res.String())
	}
	if len(progress) == 0 {
		t.Error("no progress reported")
	}
}

func TestE2ETipNpubResolvesLud16FromProfile(t *testing.T) {
	f := newTipFixture(t)
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	profile := &nostr.Event{PubKey: pk, CreatedAt: nostr.Now(), Kind: 0, Tags: nostr.Tags{},
		Content: fmt.Sprintf(`{"name":"alice","lud16":%q}`, f.address)}
	_ = profile.Sign(sk)
	f.relay.Add(profile)

	npub, _ := nip19.EncodePublicKey(pk)
	for _, target := range []string{npub, pk} {
		res, err := tipUser(context.Background(), target, 5, nil)
		if err != nil || res.LightningAddress != f.address {
			t.Fatalf("tipUser(%s) = %+v, %v", target, res, err)
		}
	}
}

func TestE2ETipWalletError(t *testing.T) {
	f := newTipFixture(t)
	f.walletReply = func(string) map[string]any {
		return map[string]any{"result_type": "pay_invoice", "error": map[string]any{"code": "INSUFFICIENT_BALANCE", "message": "not enough sats"}}
	}
	_, err := tipUser(context.Background(), f.address, 21, nil)
	var nerr *nwcError
	if !errors.As(err, &nerr) || nerr.Code != "INSUFFICIENT_BALANCE" || !strings.Contains(err.Error(), "not enough sats") {
		t.Fatalf("err = %v", err)
	}
}

func TestE2ETipWalletSilentIsUnconfirmed(t *testing.T) {
	f := newTipFixture(t)
	f.walletReply = func(string) map[string]any { return nil }
	old := nwcResponseTimeout
	nwcResponseTimeout = 700 * time.Millisecond
	t.Cleanup(func() { nwcResponseTimeout = old })

	_, err := tipUser(context.Background(), f.address, 21, nil)
	if !errors.Is(err, ErrPaymentUnconfirmed) {
		t.Fatalf("err = %v, want ErrPaymentUnconfirmed", err)
	}
	if f.requests.Load() != 1 {
		t.Fatalf("wallet saw %d requests", f.requests.Load())
	}
}

// A malicious or buggy LNURL server bills more than was asked for: hoot must
// refuse before the wallet ever sees the invoice.
func TestE2ETipRefusesInflatedInvoice(t *testing.T) {
	f := newTipFixture(t)
	f.invoiceMsat = func(r int64) int64 { return r * 100 }
	_, err := tipUser(context.Background(), f.address, 21, nil)
	if err == nil || !strings.Contains(err.Error(), "refusing to pay") {
		t.Fatalf("err = %v", err)
	}
	if n := f.requests.Load(); n != 0 {
		t.Fatalf("wallet received %d payment requests", n)
	}
}

func TestE2ETipAmountOutsideLimits(t *testing.T) {
	f := newTipFixture(t)
	f.minSendable, f.maxSendable = 10_000, 50_000
	for _, sats := range []int64{1, 100} {
		_, err := tipUser(context.Background(), f.address, sats, nil)
		if err == nil || !strings.Contains(err.Error(), "accepts 10–50 sats") {
			t.Errorf("sats=%d err = %v", sats, err)
		}
	}
}

func TestE2ETipLNURLError(t *testing.T) {
	f := newTipFixture(t)
	f.lnurlFailure = "user is on vacation"
	_, err := tipUser(context.Background(), f.address, 21, nil)
	if err == nil || !strings.Contains(err.Error(), "user is on vacation") {
		t.Fatalf("err = %v", err)
	}
}

func TestTipWithoutWalletFailsFast(t *testing.T) {
	isolate(t)
	_, err := tipUser(context.Background(), "alice@example.invalid", 21, nil)
	if err == nil || !strings.Contains(err.Error(), "hoot -nwc") {
		t.Fatalf("err = %v", err)
	}
}

func TestTipRejectsBadInput(t *testing.T) {
	isolate(t)
	if err := saveNWCURI("nostr+walletconnect://" + strings.Repeat("a1", 32) + "?relay=ws://127.0.0.1:1&secret=" + strings.Repeat("b2", 32)); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		target string
		sats   int64
		want   string
	}{
		{"alice@example.invalid", 0, "positive"},
		{"not-a-key", 21, "not a lightning address"},
		{"npub1bad", 21, "invalid npub"},
		{"@example.com", 21, "invalid lightning address"},
	} {
		if _, err := tipUser(context.Background(), c.target, c.sats, nil); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("tipUser(%q,%d) err = %v, want %q", c.target, c.sats, err, c.want)
		}
	}
}
