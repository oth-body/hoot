package tui

import (
	"errors"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"hoot/nip46"
)

func press(t *testing.T, m Model, msg tea.Msg) (Model, tea.Cmd) {
	t.Helper()
	u, cmd := m.Update(msg)
	return u.(Model), cmd
}

func isQuit(cmd tea.Cmd) bool {
	if cmd == nil {
		return false
	}
	_, ok := cmd().(tea.QuitMsg)
	return ok
}

// #78: after an Amber login the home screen shows the kind-0 name, the
// NIP-05 (with a ✓) and the about line — not just a hex prefix.
func TestHomeShowsAmberProfile(t *testing.T) {
	m := NewModel()
	m.screen = ScreenQRLogin
	pk := strings.Repeat("ab", 32)

	m, _ = press(t, m, qrSuccessMsg{pubkey: pk, profile: &nip46.ProfileMetadata{
		PubKey: pk, Name: "Satoshi", About: "Chancellor on brink\nof second bailout", NIP05: "satoshi@example.com",
	}})
	if m.screen != ScreenHome || !m.loggedIn {
		t.Fatalf("not logged in: screen=%v", m.screen)
	}
	view := m.View()
	for _, want := range []string{"Satoshi", "✓ satoshi@example.com", "Chancellor on brink of second bailout", "Logged in as Satoshi"} {
		if !strings.Contains(view, want) {
			t.Errorf("home view missing %q:\n%s", want, view)
		}
	}
}

// With no kind-0 profile the home screen falls back to a (truncated) npub.
func TestHomeFallsBackToNpub(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	npub, _ := nip19.EncodePublicKey(pk)

	m := NewModel()
	m.screen = ScreenQRLogin
	m, _ = press(t, m, qrSuccessMsg{pubkey: pk})
	view := m.View()
	if !strings.Contains(view, npub[:12]) || !strings.Contains(view, npub[len(npub)-6:]) {
		t.Errorf("home view missing npub %s:\n%s", npub, view)
	}
	if strings.Contains(view, "✓") {
		t.Errorf("NIP-05 marker shown with no profile:\n%s", view)
	}
}

func TestOneLineTruncates(t *testing.T) {
	if got := oneLine("a\n b\t c", 10); got != "a b c" {
		t.Errorf("got %q", got)
	}
	if got := oneLine(strings.Repeat("é", 100), 10); len([]rune(got)) != 10 || !strings.HasSuffix(got, "…") {
		t.Errorf("got %q", got)
	}
}

// Esc on the QR screen must return to login (not Home) and tear down the
// pairing session via onLogout.
func TestEscFromQRReturnsToLoginAndLogsOut(t *testing.T) {
	logouts := 0
	m := NewModel()
	m.onLogout = func() { logouts++ }
	m.screen = ScreenQRLogin
	m.qrData = "nostrconnect://x"

	m, cmd := press(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if isQuit(cmd) {
		t.Fatal("esc on QR screen quit the app")
	}
	if m.screen != ScreenLogin || m.loggedIn {
		t.Fatalf("screen=%v loggedIn=%v, want login screen, logged out", m.screen, m.loggedIn)
	}
	if logouts != 1 {
		t.Fatalf("onLogout called %d times, want 1", logouts)
	}

	// A connection check that was in flight must not log the user in, and
	// the retry tick must stop polling.
	m, _ = press(t, m, qrSuccessMsg{pubkey: strings.Repeat("cd", 32)})
	if m.loggedIn || m.screen != ScreenLogin {
		t.Fatal("late qrSuccessMsg logged the user in after esc")
	}
	if _, cmd := press(t, m, checkQRTickMsg{}); cmd != nil {
		t.Fatal("QR polling continued after leaving the QR screen")
	}
}

// Any non-login screen reached while logged out goes back to login on esc.
func TestEscWhileLoggedOutNeverReachesHome(t *testing.T) {
	m := NewModel()
	m.screen = ScreenFeed
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if m.screen != ScreenLogin {
		t.Fatalf("screen=%v, want login", m.screen)
	}
}

func TestEscInsideLoginSubformBacksOut(t *testing.T) {
	m := NewModel()
	m.addingProfile = true
	m.cursor = 51
	m.tempName = "x"
	m, cmd := press(t, m, tea.KeyMsg{Type: tea.KeyEsc})
	if isQuit(cmd) {
		t.Fatal("esc inside the add-profile form quit the app")
	}
	if m.cursor != 0 || m.addingProfile || m.tempName != "" {
		t.Fatalf("form not reset: cursor=%d adding=%v name=%q", m.cursor, m.addingProfile, m.tempName)
	}
	// At the top-level menu esc still quits.
	if _, cmd := press(t, m, tea.KeyMsg{Type: tea.KeyEsc}); !isQuit(cmd) {
		t.Fatal("esc on login menu should quit")
	}
}

func TestCtrlCQuitsFromAnyScreen(t *testing.T) {
	for _, s := range []Screen{ScreenLogin, ScreenQRLogin, ScreenHome, ScreenFeed, ScreenRelays} {
		m := NewModel()
		m.screen = s
		m.loggedIn = s != ScreenLogin && s != ScreenQRLogin
		if _, cmd := press(t, m, tea.KeyMsg{Type: tea.KeyCtrlC}); !isQuit(cmd) {
			t.Errorf("ctrl+c on screen %v did not quit", s)
		}
	}
}

// Switching profile must log out of the previous session and clear the
// Amber metadata so it doesn't show for the next account.
func TestSwitchProfileLogsOut(t *testing.T) {
	logouts := 0
	m := newModelFromConfig(Config{OnLogout: func() { logouts++ }})
	m.screen = ScreenQRLogin
	m, _ = press(t, m, qrSuccessMsg{pubkey: strings.Repeat("ab", 32), profile: &nip46.ProfileMetadata{Name: "A", About: "about A", NIP05: "a@x"}})

	m.cursor = 6 // [s] Switch Profile
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.screen != ScreenLogin || m.loggedIn {
		t.Fatalf("screen=%v loggedIn=%v", m.screen, m.loggedIn)
	}
	if logouts != 1 {
		t.Fatalf("onLogout called %d times", logouts)
	}
	if m.currentProfileName != "" || m.currentProfileAbout != "" || m.currentProfileNIP05 != "" || m.publicKey != "" {
		t.Fatalf("stale identity after switch: %+v", []string{m.currentProfileName, m.currentProfileAbout, m.currentProfileNIP05, m.publicKey})
	}
}

// Creating a profile must leave the model holding the private key, or the
// DMs screen reports "No private key available" right after signup.
func TestAddProfileKeepsPrivateKeyForDMs(t *testing.T) {
	var dmKey string
	m := newModelFromConfig(Config{
		OnAddProfile: func(name, nsec, pw string) (string, string, error) { return "sk-hex", "pk-hex", nil },
		OnLoadDMs:    func(sk string) ([]FeedPost, error) { dmKey = sk; return nil, nil },
	})
	m.addingProfile = true
	m.cursor = 100
	m.tempName, m.tempNsec = "me", "nsec1whatever"
	m.textInput.SetValue("pw")
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if !m.loggedIn || m.privateKey != "sk-hex" {
		t.Fatalf("loggedIn=%v privateKey=%q", m.loggedIn, m.privateKey)
	}
	m.cursor = 2 // [d] View DMs
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if dmKey != "sk-hex" {
		t.Fatalf("DMs loaded with key %q; message=%q", dmKey, m.message)
	}
}

func typeText(t *testing.T, m Model, s string) Model {
	t.Helper()
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)})
	return m
}

// The Tip screen: recipient → amount → background payment → result.
// Previously Enter on this screen did nothing at all.
func TestTipScreenFlow(t *testing.T) {
	var gotTarget string
	var gotSats int64
	m := newModelFromConfig(Config{OnTip: func(target string, sats int64) (string, error) {
		gotTarget, gotSats = target, sats
		return "Paid 21 sats to alice@example.com", nil
	}})
	m.loggedIn, m.screen, m.cursor = true, ScreenHome, 4
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.screen != ScreenTip {
		t.Fatalf("screen = %v", m.screen)
	}

	// Empty recipient is rejected.
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.tipStep != 0 || !strings.Contains(m.message, "who to tip") {
		t.Fatalf("empty recipient accepted: step=%d msg=%q", m.tipStep, m.message)
	}

	m = typeText(t, m, "alice@example.com")
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if m.tipStep != 1 || m.tipTarget != "alice@example.com" || !strings.Contains(m.View(), "To: alice@example.com") {
		t.Fatalf("not on amount step: %+v\n%s", m.tipStep, m.View())
	}

	// Bad amounts are rejected without paying.
	for _, bad := range []string{"abc", "0", "-5", "1.5"} {
		m.textInput.SetValue(bad)
		var cmd tea.Cmd
		m, cmd = press(t, m, tea.KeyMsg{Type: tea.KeyEnter})
		if cmd != nil || m.tipping || !strings.Contains(m.message, "whole number") {
			t.Fatalf("amount %q accepted (msg=%q)", bad, m.message)
		}
	}

	m.textInput.SetValue("21")
	m, cmd := press(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if !m.tipping || cmd == nil || !strings.Contains(m.View(), "Waiting for your wallet") {
		t.Fatalf("payment not started: tipping=%v\n%s", m.tipping, m.View())
	}
	// Enter while paying is ignored.
	if _, c := press(t, m, tea.KeyMsg{Type: tea.KeyEnter}); c != nil {
		t.Fatal("second payment started while one was in flight")
	}

	m, _ = press(t, m, cmd())
	if gotTarget != "alice@example.com" || gotSats != 21 {
		t.Fatalf("OnTip(%q, %d)", gotTarget, gotSats)
	}
	if m.tipping || m.tipStep != 0 || !strings.Contains(m.View(), "⚡ Paid 21 sats") {
		t.Fatalf("result not shown:\n%s", m.View())
	}
}

func TestTipScreenShowsFailure(t *testing.T) {
	m := newModelFromConfig(Config{OnTip: func(string, int64) (string, error) {
		return "", errors.New("wallet error INSUFFICIENT_BALANCE")
	}})
	m.loggedIn, m.screen = true, ScreenTip
	m.resetTipForm()
	m = typeText(t, m, "alice@example.com")
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m = typeText(t, m, "21")
	m, cmd := press(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	m, _ = press(t, m, cmd())
	if !strings.Contains(m.View(), "Tip failed: wallet error INSUFFICIENT_BALANCE") {
		t.Fatalf("failure not shown:\n%s", m.View())
	}
}

// Regression: keys were matched against shortcuts before reaching a focused
// text field. "k"/"j" moved the cursor mid-form and "r" deleted the stored
// key file. Every letter must now reach the field untouched.
func TestLettersGoToFocusedTextField(t *testing.T) {
	resetCalls := 0
	added := ""
	m := newModelFromConfig(Config{
		HasKey:     func() bool { return true },
		OnResetKey: func() error { resetCalls++; return nil },
		OnAddProfile: func(name, nsec, pw string) (string, string, error) {
			added = pw
			return "sk", "pk", nil
		},
	})
	m.addingProfile = true
	m.cursor = 100
	m.tempName, m.tempNsec = "me", "nsec1whatever"
	m.textInput.Focus()

	const pw = "jerk-quark-dpfest"
	for _, r := range pw {
		m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	if m.cursor != 100 || m.textInput.Value() != pw {
		t.Fatalf("form state broken by typing: cursor=%d value=%q", m.cursor, m.textInput.Value())
	}
	if resetCalls != 0 {
		t.Fatal("typing 'r' deleted the stored key")
	}
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if !m.loggedIn || added != pw {
		t.Fatalf("profile not created with typed password: loggedIn=%v pw=%q", m.loggedIn, added)
	}
}

func TestComposerAcceptsShortcutLetters(t *testing.T) {
	var posted string
	m := newModelFromConfig(Config{OnPost: func(s string) error { posted = s; return nil }})
	m.loggedIn = true
	m.screen = ScreenHome
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("p")})
	if m.screen != ScreenPost {
		t.Fatalf("p did not open the composer: screen=%v", m.screen)
	}
	for _, r := range "quit? press q, r, s, d" {
		var cmd tea.Cmd
		m, cmd = press(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		if isQuit(cmd) {
			t.Fatalf("typing %q quit the app", r)
		}
	}
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if posted != "quit? press q, r, s, d" {
		t.Fatalf("posted %q", posted)
	}
}

// The home menu advertises [p] [f] [d] [e] [t] [r] [s] [q]; only q worked.
func TestHomeShortcuts(t *testing.T) {
	cases := map[string]Screen{"p": ScreenPost, "f": ScreenFeed, "d": ScreenDMs, "e": ScreenReplies, "t": ScreenTip, "r": ScreenRelays, "s": ScreenLogin}
	for key, want := range cases {
		m := newModelFromConfig(Config{})
		m.loggedIn, m.screen = true, ScreenHome
		m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
		if m.screen != want {
			t.Errorf("%q → screen %v, want %v", key, m.screen, want)
		}
	}
	m := newModelFromConfig(Config{})
	m.loggedIn, m.screen = true, ScreenHome
	if _, cmd := press(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")}); !isQuit(cmd) {
		t.Error("q did not quit")
	}
}

// "r" on the login menu used to silently delete the hoot -s key file.
func TestLoginRDoesNotDeleteKey(t *testing.T) {
	resetCalls := 0
	m := newModelFromConfig(Config{HasKey: func() bool { return true }, OnResetKey: func() error { resetCalls++; return nil }})
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("r")})
	if resetCalls != 0 {
		t.Fatal("r on the login screen deleted the stored key")
	}
}

func TestRepliesArrowsStillScroll(t *testing.T) {
	m := newModelFromConfig(Config{})
	m.loggedIn, m.screen = true, ScreenReplies
	m.replyPosts = make([]FeedPost, 10)
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyDown})
	if m.replyScroll != 1 {
		t.Fatalf("replyScroll = %d", m.replyScroll)
	}
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("j")})
	if m.replyScroll != 1 || m.textInput.Value() != "j" {
		t.Fatalf("j should be typed into the event-ID field: scroll=%d value=%q", m.replyScroll, m.textInput.Value())
	}
}

func TestHomeShowsFullNpub(t *testing.T) {
	sk := nostr.GeneratePrivateKey()
	pk, _ := nostr.GetPublicKey(sk)
	npub, _ := nip19.EncodePublicKey(pk)
	m := newModelFromConfig(Config{})
	m.loggedIn, m.screen, m.publicKey, m.currentProfileName = true, ScreenHome, pk, "main"
	if v := m.View(); !strings.Contains(v, npub) {
		t.Fatalf("home view missing full npub %s:\n%s", npub, v)
	}
}

// Regression: the prompt said "Leave empty to skip saving", but an empty
// password saved the nsec encrypted with "" — effectively unprotected.
func TestAddProfileRequiresPassword(t *testing.T) {
	called := false
	m := newModelFromConfig(Config{
		OnAddProfile: func(name, nsec, pw string) (string, string, error) { called = true; return "sk", "pk", nil },
	})
	m.addingProfile = true
	m.cursor = 100
	m.tempName, m.tempNsec = "me", "nsec1whatever"
	if strings.Contains(m.View(), "skip saving") {
		t.Fatal("prompt still offers to skip saving")
	}
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyEnter})
	if called || m.loggedIn || m.cursor != 100 || !strings.Contains(m.message, "choose a password") {
		t.Fatalf("empty password accepted: called=%v loggedIn=%v cursor=%d msg=%q", called, m.loggedIn, m.cursor, m.message)
	}
}
