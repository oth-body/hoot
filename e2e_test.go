package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"hoot/cache"
	"hoot/internal/testrelay"
	"hoot/nip46"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip19"
)

// isolate points hoot's config dir at a temp dir, moves the working
// directory away from the repo's own relays.txt (loadRelays checks ./ first),
// writes relays.txt with the given relays, and restores hoot's globals after
// the test.
func isolate(t *testing.T, relays ...string) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", dir)
	t.Setenv("APPDATA", dir)
	t.Chdir(t.TempDir())

	if len(relays) > 0 {
		if err := os.MkdirAll(getConfigDir(), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(getConfigDir(), "relays.txt"), []byte(strings.Join(relays, "\n")), 0600); err != nil {
			t.Fatal(err)
		}
	}

	oldKey, oldSess, oldCache := localPrivateKey, nip46Session, eventCache
	localPrivateKey, nip46Session, eventCache = "", nil, nil
	t.Cleanup(func() {
		if nip46Session != nil && nip46Session != oldSess {
			nip46Session.Close()
		}
		localPrivateKey, nip46Session, eventCache = oldKey, oldSess, oldCache
	})
	return dir
}

// startRelay starts an in-process relay for the test.
//
// Relay-backed tests skip under -race: go-nostr v0.50's Relay.close() reads
// r.Connection while the library's own connection goroutine sets it to nil
// (still present upstream, which is deprecated in favour of
// fiatjaf.com/nostr). Every relay disconnect can trip the detector no matter
// what hoot does. CI runs these tests in a separate non-race step.
func startRelay(t *testing.T) *testrelay.Relay {
	t.Helper()
	if raceDetector {
		t.Skip("skipped under -race: upstream go-nostr Relay.close data race; run without -race")
	}
	r := testrelay.Start()
	t.Cleanup(r.Close)
	return r
}

func signedNote(t *testing.T, sk, content string, at time.Time) *nostr.Event {
	t.Helper()
	pk, _ := nostr.GetPublicKey(sk)
	ev := &nostr.Event{PubKey: pk, CreatedAt: nostr.Timestamp(at.Unix()), Kind: 1, Tags: nostr.Tags{}, Content: content}
	if err := ev.Sign(sk); err != nil {
		t.Fatal(err)
	}
	return ev
}

func signedDM(t *testing.T, fromSK, toPK, text string, at time.Time) *nostr.Event {
	t.Helper()
	fromPK, _ := nostr.GetPublicKey(fromSK)
	ss, err := nip04.ComputeSharedSecret(toPK, fromSK)
	if err != nil {
		t.Fatal(err)
	}
	ct, err := nip04.Encrypt(text, ss)
	if err != nil {
		t.Fatal(err)
	}
	ev := &nostr.Event{PubKey: fromPK, CreatedAt: nostr.Timestamp(at.Unix()), Kind: 4, Tags: nostr.Tags{{"p", toPK}}, Content: ct}
	if err := ev.Sign(fromSK); err != nil {
		t.Fatal(err)
	}
	return ev
}

func TestE2EPublishFromTUIAppearsInFeed(t *testing.T) {
	relay := startRelay(t)
	isolate(t, relay.URL)

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	useLocalKey(sk)

	if err := publishPostTUI("hello from the e2e test"); err != nil {
		t.Fatalf("publishPostTUI: %v", err)
	}
	evs := relay.Events()
	if len(evs) != 1 || evs[0].PubKey != pk || evs[0].Content != "hello from the e2e test" {
		t.Fatalf("relay got %+v", evs)
	}

	posts, err := getFeedPosts()
	if err != nil {
		t.Fatal(err)
	}
	if len(posts) != 1 || posts[0].Content != "hello from the e2e test" || posts[0].Author != pk {
		t.Fatalf("feed = %+v", posts)
	}
}

// Regression: with 20 events already cached, the old getFeedPosts filled its
// 20-post quota from the cache and never showed anything newer.
func TestE2EFeedIsNotFrozenByCache(t *testing.T) {
	relay := startRelay(t)
	dir := isolate(t, relay.URL)

	c, err := cache.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	eventCache = c

	old := nostr.GeneratePrivateKey()
	for i := 0; i < 25; i++ {
		ev := signedNote(t, old, fmt.Sprintf("stale %d", i), time.Now().Add(-48*time.Hour+time.Duration(i)*time.Minute))
		if err := c.StoreEvent(ev, 24*time.Hour); err != nil {
			t.Fatal(err)
		}
	}

	relay.Add(signedNote(t, nostr.GeneratePrivateKey(), "fresh post", time.Now()))

	posts, err := getFeedPosts()
	if err != nil {
		t.Fatal(err)
	}
	if len(posts) == 0 || posts[0].Content != "fresh post" {
		t.Fatalf("expected newest relay post first, got %+v", posts)
	}
}

func TestE2EFeedFallsBackToCacheWhenRelaysDown(t *testing.T) {
	relay := startRelay(t)
	dir := isolate(t, relay.URL)
	relay.Close() // nothing answers

	c, err := cache.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	eventCache = c
	sk := nostr.GeneratePrivateKey()
	_ = c.StoreEvent(signedNote(t, sk, "older", time.Now().Add(-2*time.Hour)), time.Hour*24)
	_ = c.StoreEvent(signedNote(t, sk, "newer", time.Now().Add(-1*time.Hour)), time.Hour*24)

	posts, err := getFeedPosts()
	if err != nil {
		t.Fatal(err)
	}
	if len(posts) != 2 || posts[0].Content != "newer" {
		t.Fatalf("expected cached posts newest-first, got %+v", posts)
	}
}

// Regression: getDMs used to ask for the 50 newest kind-4 events on the
// whole relay and filter locally (missing the user's DMs whenever the relay
// had other traffic), and decrypted sent DMs with the wrong shared secret.
func TestE2EDMsSentAndReceived(t *testing.T) {
	relay := startRelay(t)
	isolate(t, relay.URL)

	alice, bob := nostr.GeneratePrivateKey(), nostr.GeneratePrivateKey()
	alicePK, _ := nostr.GetPublicKey(alice)
	bobPK, _ := nostr.GetPublicKey(bob)

	base := time.Now().Add(-time.Hour)
	relay.Add(signedDM(t, alice, bobPK, "hi bob", base))
	relay.Add(signedDM(t, bob, alicePK, "hi alice", base.Add(time.Minute)))

	// 60 newer DMs between strangers: enough to push alice's out of a
	// global "newest 50 kind-4" query.
	for i := 0; i < 60; i++ {
		c, d := nostr.GeneratePrivateKey(), nostr.GeneratePrivateKey()
		dPK, _ := nostr.GetPublicKey(d)
		relay.Add(signedDM(t, c, dPK, "noise", base.Add(time.Duration(10+i)*time.Minute)))
	}

	dms, err := getDMs(alice)
	if err != nil {
		t.Fatal(err)
	}
	if len(dms) != 2 {
		t.Fatalf("want 2 DMs, got %d: %+v", len(dms), dms)
	}
	if dms[0].Content != "[DM from]: hi alice" || dms[0].Author != bobPK {
		t.Errorf("newest DM = %+v", dms[0])
	}
	if want := "[DM to " + bobPK[:8] + "...]: hi bob"; dms[1].Content != want || dms[1].Author != alicePK {
		t.Errorf("sent DM = %+v, want content %q", dms[1], want)
	}
}

func TestDecryptDMRejectsUnrelatedAndMalformed(t *testing.T) {
	a, b, c := nostr.GeneratePrivateKey(), nostr.GeneratePrivateKey(), nostr.GeneratePrivateKey()
	aPK, _ := nostr.GetPublicKey(a)
	cPK, _ := nostr.GetPublicKey(c)
	ev := signedDM(t, b, cPK, "not for a", time.Now())
	if _, ok := decryptDM(ev, a, aPK); ok {
		t.Error("decrypted a DM between two other people")
	}
	// Sent DM with no p tag must not panic.
	noP := signedDM(t, a, cPK, "x", time.Now())
	noP.Tags = nostr.Tags{}
	if _, ok := decryptDM(noP, a, aPK); ok {
		t.Error("accepted a sent DM with no recipient")
	}
}

func TestE2EProfileCreatedInTUIWorksForPosting(t *testing.T) {
	relay := startRelay(t)
	isolate(t, relay.URL)

	sk := nostr.GeneratePrivateKey()
	nsec, _ := nip19.EncodePrivateKey(sk)
	p, err := AddProfile("e2e", nsec, "pw")
	if err != nil {
		t.Fatal(err)
	}
	gotSK, gotPK, err := UnlockProfile(p.ID, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if gotSK != sk || gotPK != p.PublicKey {
		t.Fatalf("UnlockProfile = %q,%q", gotSK, gotPK)
	}
	if _, _, err := UnlockProfile(p.ID, "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}
}

// Regression: a legacy key stored by `hoot -s -k nsec1...` is saved as the
// raw nsec string; after MigrateLegacyKey the profile had no pubkey and
// UnlockProfile returned the nsec as if it were hex, so signing failed.
func TestE2EMigratedLegacyKeyUnlocksAndPosts(t *testing.T) {
	relay := startRelay(t)
	isolate(t, relay.URL)

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	nsec, _ := nip19.EncodePrivateKey(sk)
	if err := saveKey(nsec, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	if err := MigrateLegacyKey(); err != nil {
		t.Fatal(err)
	}
	list, last, err := GetProfileList()
	if err != nil || len(list) != 1 || list[0].ID != last {
		t.Fatalf("profiles after migration: %+v %q %v", list, last, err)
	}

	gotSK, gotPK, err := UnlockProfile(last, "pw")
	if err != nil {
		t.Fatal(err)
	}
	if gotSK != sk || gotPK != pk {
		t.Fatalf("UnlockProfile = %q,%q want %q,%q", gotSK, gotPK, sk, pk)
	}
	list, _, _ = GetProfileList()
	if list[0].PublicKey != pk {
		t.Errorf("pubkey not backfilled: %+v", list[0])
	}

	useLocalKey(gotSK)
	if err := publishPostTUI("from migrated profile"); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if evs := relay.Events(); len(evs) != 1 || evs[0].PubKey != pk {
		t.Fatalf("relay got %+v", evs)
	}
}

// Regression: publishPostTUI prefers nip46Session over the local key, and
// nothing cleared the session when the user abandoned a QR scan or switched
// to a local profile, so posts went to the (unpaired) remote signer.
func TestE2ELocalLoginEndsStaleRemoteSession(t *testing.T) {
	relay := startRelay(t)
	isolate(t, relay.URL)

	_, sess, err := nip46.GenerateConnectURI([]string{relay.URL}, "hoot-test")
	if err != nil {
		t.Fatal(err)
	}
	nip46Session = sess

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	useLocalKey(sk)
	if nip46Session != nil {
		t.Fatal("remote session still active after local login")
	}
	if err := publishPostTUI("signed locally"); err != nil {
		t.Fatalf("publish: %v", err)
	}
	if evs := relay.Events(); len(evs) != 1 || evs[0].PubKey != pk {
		t.Fatalf("relay got %+v", evs)
	}
}

// Drives the real CLI entry point (main) in-process with a profile created
// through the TUI path and no legacy key file. Previously every CLI command
// said "No private key found" in this situation.
func TestE2ECLIPostsWithTUIProfile(t *testing.T) {
	relay := startRelay(t)
	isolate(t, relay.URL)

	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	nsec, _ := nip19.EncodePrivateKey(sk)
	if _, err := AddProfile("cli", nsec, "pw"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOOT_PASSWORD", "pw")

	oldArgs, oldFlags := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = oldArgs, oldFlags })
	os.Args = []string{"hoot", "-m", "posted via CLI #e2e"}
	flag.CommandLine = flag.NewFlagSet("hoot", flag.ContinueOnError)

	main()

	evs := relay.Events()
	if len(evs) != 1 || evs[0].PubKey != pk || evs[0].Content != "posted via CLI #e2e" {
		t.Fatalf("relay got %+v", evs)
	}
	if tag := evs[0].Tags.GetFirst([]string{"t"}); tag == nil || (*tag)[1] != "e2e" {
		t.Errorf("hashtag not tagged: %v", evs[0].Tags)
	}
}

func TestNormalizePrivKey(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	nsec, _ := nip19.EncodePrivateKey(sk)
	for _, in := range []string{sk, nsec, "  " + nsec + "\n"} {
		if got, err := normalizePrivKey(in); err != nil || got != sk {
			t.Errorf("normalizePrivKey(%q) = %q, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "nsec1garbage", "abc", strings.Repeat("z", 64)} {
		if _, err := normalizePrivKey(bad); err == nil {
			t.Errorf("normalizePrivKey(%q) accepted", bad)
		}
	}
}

func TestDecryptKeyRejectsTruncatedCiphertext(t *testing.T) {
	sk, err := encryptKey([]byte("secret"), []byte("pw"))
	if err != nil {
		t.Fatal(err)
	}
	sk.EncryptedKey = sk.EncryptedKey[:10]
	if _, err := decryptKey(sk, []byte("pw")); err == nil {
		t.Fatal("expected error, not a panic or success")
	}
}

// runMainCapture runs main() in-process with args and returns its stdout.
func runMainCapture(t *testing.T, args ...string) string {
	t.Helper()
	oldArgs, oldFlags, oldStdout := os.Args, flag.CommandLine, os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Args = append([]string{"hoot"}, args...)
	flag.CommandLine = flag.NewFlagSet("hoot", flag.ContinueOnError)
	os.Stdout = w
	defer func() { os.Args, flag.CommandLine, os.Stdout = oldArgs, oldFlags, oldStdout }()
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	main()
	w.Close()
	return <-done
}

// -npub prints just the npub, and for TUI profiles doesn't need the
// password (the pubkey is stored unencrypted). With no HOOT_PASSWORD and no
// TTY, reaching the password prompt would log.Fatal and kill the test.
func TestNpubFlagWithProfileNeedsNoPassword(t *testing.T) {
	isolate(t)
	t.Setenv("HOOT_PASSWORD", "")
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	nsec, _ := nip19.EncodePrivateKey(sk)
	if _, err := AddProfile("main", nsec, "pw"); err != nil {
		t.Fatal(err)
	}
	want, _ := nip19.EncodePublicKey(pk)
	if got := runMainCapture(t, "-npub"); got != want+"\n" {
		t.Fatalf("stdout = %q, want %q", got, want+"\n")
	}
}

// With a legacy hoot -s key the pubkey isn't stored, so the key is unlocked;
// stdout must still contain only the npub (prompts/progress go to stderr).
func TestNpubFlagWithLegacyKey(t *testing.T) {
	isolate(t)
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	nsec, _ := nip19.EncodePrivateKey(sk)
	if err := saveKey(nsec, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOOT_PASSWORD", "pw")
	want, _ := nip19.EncodePublicKey(pk)
	if got := runMainCapture(t, "-npub"); got != want+"\n" {
		t.Fatalf("stdout = %q, want %q", got, want+"\n")
	}
}
