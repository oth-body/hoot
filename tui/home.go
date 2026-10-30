package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/nbd-wtf/go-nostr/nip19"
)

func (m Model) handleHomeEnter() (tea.Model, tea.Cmd) {
	switch m.cursor {
	case 0: // Post
		m.screen = ScreenPost
		m.textInput.Placeholder = "What's on your mind?"
		m.textInput.EchoMode = textinput.EchoNormal
		m.textInput.Reset()
		m.textInput.Focus()
	case 1: // Feed
		m.screen = ScreenFeed
		return m, m.reloadFeed()
	case 2: // DMs
		m.screen = ScreenDMs
		m.dmPosts = nil
		m.dmScroll = 0
		m.message = ""
		if m.onLoadDMs != nil {
			// Works with a local key or a remote signer (Amber decrypts).
			m.dmLoading = true
			return m, m.startLoad(ScreenDMs, m.onLoadDMs)
		}
	case 3: // Replies/Reactions
		m.screen = ScreenReplies
		m.threadPost = nil
		m.replyLoading = false
		m.replyPosts = nil
		m.replyScroll = 0
		m.textInput.Placeholder = "Enter event ID to view replies..."
		m.textInput.Reset()
		m.textInput.Focus()
	case 4: // Tip
		m.screen = ScreenTip
		m.message = ""
		if !m.tipping {
			m.resetTipForm()
		}
	case 5: // Relays
		m.screen = ScreenRelays
		m.addingRelay = false
		m.selectedRelay = 0
		if m.onLoadRelays != nil {
			relays, err := m.onLoadRelays()
			if err == nil {
				m.relays = relays
			}
		}
	case 6: // Switch Profile
		// Go back to login screen to select a different profile.
		// logout() also tears down the host's signing session so the
		// previous account can't sign posts for the next one.
		m.logout()
		m.screen = ScreenLogin
		m.step = stepMenu
		m.cursor = 0
		m.textInput.Reset()
		m.reloadProfiles()
		m.selectLastUsedProfile()
	case 7: // Quit
		return m, tea.Quit
	}
	return m, nil
}

func (m Model) viewHome() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("🦉 Hoot"))
	// Show current profile name if set
	if m.currentProfileName != "" {
		b.WriteString(menuStyle.Render(fmt.Sprintf(" - %s", m.currentProfileName)))
	} else if npub := shortNpub(m.publicKey); npub != "" {
		b.WriteString(menuStyle.Render(" - " + npub))
	}
	b.WriteString("\n")
	// Full npub, so it can be copied and shared from the terminal.
	if npub, err := nip19.EncodePublicKey(m.publicKey); err == nil && m.publicKey != "" {
		b.WriteString(menuStyle.Render(npub))
		b.WriteString("\n")
	}
	// Kind-0 metadata from the Amber/NIP-46 login (#78). Rendered dim,
	// under the title. NIP-05 gets a ✓ so it reads as an identity at a
	// glance. Both are single-lined and truncated so a long bio can't
	// push the menu off a small terminal.
	if m.currentProfileNIP05 != "" {
		b.WriteString(menuStyle.Render("✓ " + oneLine(m.currentProfileNIP05, 60)))
		b.WriteString("\n")
	}
	if m.currentProfileAbout != "" {
		b.WriteString(menuStyle.Render(oneLine(m.currentProfileAbout, 72)))
		b.WriteString("\n")
	}
	b.WriteString("\n")

	menuItems := []string{
		"[p] Post a message",
		"[f] View feed",
		"[d] View DMs",
		"[e] View replies/reactions",
		"[t] Tip someone",
		"[r] Manage Relays",
		"[s] Switch Profile",
		"[q] Quit",
	}

	for i, item := range menuItems {
		if i == m.cursor {
			b.WriteString(selectedStyle.Render("→ " + item))
		} else {
			b.WriteString(menuStyle.Render("  " + item))
		}
		b.WriteString("\n")
	}

	// Clamp cursor
	if m.cursor >= len(menuItems) {
		m.cursor = len(menuItems) - 1
	}

	return b.String()
}

// homeShortcuts maps the letters shown in the home menu ("[p] Post a
// message", ...) to their menu index.
var homeShortcuts = map[string]int{
	"p": 0, "f": 1, "d": 2, "e": 3, "t": 4, "r": 5, "s": 6, "q": 7,
}

// shortNpub renders a hex pubkey as a truncated npub ("npub1abcdefg…uvwxyz").
// Falls back to a hex prefix if the key can't be encoded, and to "" for an
// empty key.
func shortNpub(hexPub string) string {
	if hexPub == "" {
		return ""
	}
	npub, err := nip19.EncodePublicKey(hexPub)
	if err != nil || len(npub) < 20 {
		if len(hexPub) > 16 {
			return hexPub[:16] + "..."
		}
		return hexPub
	}
	return npub[:12] + "…" + npub[len(npub)-6:]
}

// oneLine collapses whitespace (including newlines) and truncates to max
// runes, appending an ellipsis when it cuts.
func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	r := []rune(s)
	if len(r) > max {
		return string(r[:max-1]) + "…"
	}
	return s
}
