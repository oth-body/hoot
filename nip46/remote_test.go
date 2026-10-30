package nip46

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"hoot/internal/testrelay"
	"hoot/internal/testsigner"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip44"
)

func clearProxies(t *testing.T) {
	for _, v := range proxyEnvVars {
		t.Setenv(v, "")
	}
}

// pairedSession returns a session already paired with a fake signer.
func pairedSession(t *testing.T, sig func(*testsigner.Signer)) (*Session, *testsigner.Signer, string) {
	t.Helper()
	clearProxies(t)
	r := testrelay.Start()
	t.Cleanup(r.Close)
	userSK := nostr.GeneratePrivateKey()
	s, err := testsigner.Start(r.URL, userSK)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if sig != nil {
		sig(s)
	}
	_, sess, err := GenerateConnectURI([]string{r.URL}, "test")
	if err != nil {
		t.Fatal(err)
	}
	sess.RelayURLs = []string{r.URL} // no public fallback relays in tests
	if err := sess.ConnectRelays(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sess.Close)
	sess.SignerPublicKey = s.PubKey
	return sess, s, userSK
}

func TestRemoteSignAndCrypto(t *testing.T) {
	sess, signer, userSK := pairedSession(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	pk, err := sess.GetPublicKey(ctx)
	if err != nil || pk != signer.UserPubKey {
		t.Fatalf("GetPublicKey = %q, %v", pk, err)
	}

	ev := nostr.Event{Kind: 1, Content: "signed remotely", CreatedAt: nostr.Now(), Tags: nostr.Tags{}}
	if err := sess.SignEvent(ctx, &ev); err != nil {
		t.Fatal(err)
	}
	if ok, _ := ev.CheckSignature(); !ok || ev.PubKey != pk {
		t.Fatalf("bad signed event %+v", ev)
	}

	peerSK := nostr.GeneratePrivateKey()
	peer, _ := nostr.GetPublicKey(peerSK)
	ct, err := sess.Encrypt44(ctx, peer, "secret")
	if err != nil {
		t.Fatal(err)
	}
	ck, _ := nip44.GenerateConversationKey(pk, peerSK)
	if got, err := nip44.Decrypt(ct, ck); err != nil || got != "secret" {
		t.Fatalf("peer decrypt = %q, %v", got, err)
	}
	if got, err := sess.Decrypt44(ctx, peer, ct); err != nil || got != "secret" {
		t.Fatalf("Decrypt44 = %q, %v", got, err)
	}
	ct04, _ := sess.Encrypt04(ctx, peer, "old")
	if got, err := sess.Decrypt04(ctx, peer, ct04); err != nil || got != "old" {
		t.Fatalf("nip04 round trip = %q, %v", got, err)
	}
	_ = userSK
}

// Regression: sendRequest published before subscribing, so a signer that
// answered instantly was missed (kind 24133 isn't stored by relays), and it
// accepted any response, so concurrent requests could get each other's
// results.
func TestConcurrentRequestsGetTheirOwnResponses(t *testing.T) {
	sess, _, _ := pairedSession(t, func(s *testsigner.Signer) { s.Reorder = true })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// With Reorder the signer holds each answer and sends it after the
	// next one, so responses arrive out of order in pairs (12 requests).
	peer, _ := nostr.GetPublicKey(nostr.GeneratePrivateKey())
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			want := fmt.Sprint("message ", i)
			ct, err := sess.Encrypt04(ctx, peer, want)
			if err != nil {
				errs <- err
				return
			}
			got, err := sess.Decrypt04(ctx, peer, ct)
			if err != nil || got != want {
				errs <- fmt.Errorf("request %d got %q (%v)", i, got, err)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

func TestSignEventRejectsTamperedResult(t *testing.T) {
	sess, _, _ := pairedSession(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if _, err := sess.GetPublicKey(ctx); err != nil {
		t.Fatal(err)
	}
	sess.UserPublicKey = nostr.GeneratePrivateKey() // pretend we expect another key
	ev := nostr.Event{Kind: 1, Content: "x", CreatedAt: nostr.Now(), Tags: nostr.Tags{}}
	if err := sess.SignEvent(ctx, &ev); err == nil {
		t.Fatal("accepted an event signed with a different key")
	}
}
