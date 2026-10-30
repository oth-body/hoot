package relay

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"hoot/internal/testrelay"

	"github.com/nbd-wtf/go-nostr"
)

func note(t testing.TB, sk, content string, at nostr.Timestamp) nostr.Event {
	t.Helper()
	pk, _ := nostr.GetPublicKey(sk)
	ev := nostr.Event{PubKey: pk, CreatedAt: at, Kind: 1, Tags: nostr.Tags{}, Content: content}
	if err := ev.Sign(sk); err != nil {
		t.Fatal(err)
	}
	return ev
}

func start(t testing.TB) *testrelay.Relay {
	t.Helper()
	r := testrelay.Start()
	t.Cleanup(r.Close)
	return r
}

func ctxT(t testing.TB) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func TestPublishAndQuery(t *testing.T) {
	srv := start(t)
	r, err := Connect(ctxT(t), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()

	sk := nostr.GeneratePrivateKey()
	for i := 0; i < 3; i++ {
		if err := r.Publish(ctxT(t), note(t, sk, fmt.Sprint("n", i), nostr.Timestamp(1000+i))); err != nil {
			t.Fatalf("publish: %v", err)
		}
	}
	ch, err := r.QueryEvents(ctxT(t), nostr.Filter{Kinds: []int{1}, Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for ev := range ch { // must terminate at EOSE
		got = append(got, ev.Content)
	}
	if strings.Join(got, ",") != "n2,n1" {
		t.Fatalf("got %v", got)
	}
}

func TestPublishRejected(t *testing.T) {
	srv := start(t)
	r, _ := Connect(ctxT(t), srv.URL)
	defer r.Close()
	ev := note(t, nostr.GeneratePrivateKey(), "x", 1)
	ev.Content = "tampered" // signature no longer matches
	err := r.Publish(ctxT(t), ev)
	if err == nil || !strings.Contains(err.Error(), "bad signature") {
		t.Fatalf("err = %v", err)
	}
}

// Relays aren't trusted: events with bad signatures or that don't match the
// filter are dropped.
func TestDropsForgedAndUnrequestedEvents(t *testing.T) {
	srv := start(t)
	sk := nostr.GeneratePrivateKey()
	good := note(t, sk, "good", 10)
	forged := note(t, sk, "forged", 11)
	forged.Content = "changed after signing"
	kind7 := note(t, sk, "+", 12)
	kind7.Kind = 7 // not requested (signature now also wrong; filter check is first)
	srv.Add(&good)
	srv.Add(&forged)
	srv.Add(&kind7)

	r, _ := Connect(ctxT(t), srv.URL)
	defer r.Close()
	ch, _ := r.QueryEvents(ctxT(t), nostr.Filter{Kinds: []int{1}})
	var got []string
	for ev := range ch {
		got = append(got, ev.Content)
	}
	if len(got) != 1 || got[0] != "good" {
		t.Fatalf("got %v", got)
	}
}

func TestLiveSubscriptionAndCtxCancel(t *testing.T) {
	srv := start(t)
	r, _ := Connect(ctxT(t), srv.URL)
	defer r.Close()

	ctx, cancel := context.WithCancel(context.Background())
	sub, err := r.Subscribe(ctx, nostr.Filters{{Kinds: []int{1}}})
	if err != nil {
		t.Fatal(err)
	}
	<-sub.EndOfStoredEvents

	ev := note(t, nostr.GeneratePrivateKey(), "live", nostr.Now())
	srv.Publish(&ev)
	select {
	case got := <-sub.Events:
		if got.Content != "live" {
			t.Fatalf("got %q", got.Content)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("live event not delivered")
	}

	cancel()
	select {
	case _, ok := <-sub.Events:
		if ok {
			t.Fatal("unexpected event after cancel")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Events not closed after ctx cancel")
	}
}

func TestServerDropClosesEverything(t *testing.T) {
	srv := testrelay.Start()
	r, _ := Connect(ctxT(t), srv.URL)
	sub, _ := r.Subscribe(context.Background(), nostr.Filters{{Kinds: []int{1}}})
	srv.Close() // relay goes away

	select {
	case _, ok := <-sub.Events:
		if ok {
			t.Fatal("unexpected event")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("subscription not closed when relay dropped")
	}
	if r.IsConnected() {
		t.Fatal("still reports connected")
	}
	if err := r.Publish(ctxT(t), note(t, nostr.GeneratePrivateKey(), "x", 1)); !errors.Is(err, ErrClosed) {
		t.Fatalf("publish after drop: %v", err)
	}
	if sub.Err() == nil {
		t.Error("Err() should report why the subscription ended")
	}
}

// A consumer that stops reading must not wedge Close (the reader may be
// blocked delivering into a full channel).
func TestCloseWithStalledConsumer(t *testing.T) {
	srv := start(t)
	sk := nostr.GeneratePrivateKey()
	for i := 0; i < 200; i++ {
		ev := note(t, sk, fmt.Sprint(i), nostr.Timestamp(i+1))
		srv.Add(&ev)
	}
	r, _ := Connect(ctxT(t), srv.URL)
	sub, _ := r.Subscribe(context.Background(), nostr.Filters{{Kinds: []int{1}}})
	time.Sleep(200 * time.Millisecond) // let the 64-slot buffer fill and the reader block

	done := make(chan struct{})
	go func() { sub.Close(); r.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close deadlocked")
	}
}

// Hammer concurrent subscribe/publish/close under -race: this is the class
// of bug (close racing the connection goroutine) that motivated the package.
func TestConcurrentUseIsRaceFree(t *testing.T) {
	srv := start(t)
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sk := nostr.GeneratePrivateKey()
			for i := 0; i < 10; i++ {
				r, err := Connect(context.Background(), srv.URL)
				if err != nil {
					t.Error(err)
					return
				}
				sub, _ := r.Subscribe(context.Background(), nostr.Filters{{Kinds: []int{1}, Limit: 5}})
				_ = r.Publish(context.Background(), note(t, sk, "x", nostr.Now()))
				if i%2 == 0 {
					sub.Close()
				}
				go r.Close()
				r.Close()
			}
		}()
	}
	wg.Wait()
}

func TestQueryAllAndPublishAll(t *testing.T) {
	a, b := start(t), start(t)
	dead := testrelay.Start()
	dead.Close()

	sk := nostr.GeneratePrivateKey()
	shared := note(t, sk, "on both", 5)
	onlyB := note(t, sk, "only b", 9)
	a.Add(&shared)
	b.Add(&shared)
	b.Add(&onlyB)

	evs, fails := QueryAll(ctxT(t), []string{a.URL, b.URL, dead.URL, b.URL}, nostr.Filter{Kinds: []int{1}})
	if len(evs) != 2 || evs[0].Content != "only b" || evs[1].Content != "on both" {
		t.Fatalf("events = %v", evs)
	}
	if len(fails) != 1 || fails[dead.URL] == nil {
		t.Fatalf("failures = %v", fails)
	}

	ev := note(t, sk, "broadcast", 20)
	ok, fails, err := PublishAll(ctxT(t), []string{a.URL, dead.URL, b.URL}, ev)
	if err != nil || len(ok) != 2 || len(fails) != 1 {
		t.Fatalf("PublishAll = %v %v %v", ok, fails, err)
	}
	if _, _, err := PublishAll(ctxT(t), []string{dead.URL}, ev); err == nil {
		t.Fatal("expected error when no relay accepts")
	}
}
