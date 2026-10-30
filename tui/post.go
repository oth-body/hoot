package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/nbd-wtf/go-nostr/nip19"
)

func (m Model) handlePostEnter() (tea.Model, tea.Cmd) {
	content := m.textInput.Value()
	if content == "" {
		m.message = "Message cannot be empty"
		m.messageStyle = errorStyle
		return m, nil
	}

	if m.posting {
		return m, nil
	}
	if m.dmAskRecipient {
		pk, err := parseRecipient(content)
		if err != nil {
			m.message = err.Error()
			m.messageStyle = errorStyle
			return m, nil
		}
		m.dmAskRecipient = false
		m.dmTo, m.dmToLabel = pk, shortNpub(pk)
		m.message = ""
		m.textInput.Placeholder = "Write a private message..."
		m.textInput.Reset()
		return m, nil
	}
	if m.dmTo != "" {
		m.posting = true
		m.message = ""
		send, to := m.onSendDM, m.dmTo
		return m, func() tea.Msg { return postedMsg{err: send(to, content)} }
	}
	if m.replyTo != nil {
		if m.onReply == nil {
			return m, nil
		}
		m.posting = true
		m.message = ""
		reply, parent := m.onReply, m.replyTo.ID
		return m, func() tea.Msg { return postedMsg{err: reply(parent, content)} }
	}
	if m.onPost == nil {
		return m, nil
	}
	m.posting = true
	m.message = ""
	post := m.onPost
	return m, func() tea.Msg { return postedMsg{err: post(content)} }
}

func (m Model) viewPost() string {
	var b strings.Builder

	if m.composingDM() {
		b.WriteString(titleStyle.Render("✉ Private message"))
		b.WriteString("\n\n")
		if m.dmAskRecipient {
			b.WriteString(menuStyle.Render("To (npub or hex public key):"))
		} else {
			b.WriteString(menuStyle.Render("To: " + m.dmToLabel + "  🔒 end-to-end encrypted (NIP-17)"))
		}
		b.WriteString("\n\n")
	} else if m.replyTo != nil {
		b.WriteString(titleStyle.Render("↩ Reply"))
		b.WriteString("\n\n")
		b.WriteString(menuStyle.Render("Replying to " + authorLabel(*m.replyTo) + ": " + truncateRunes(oneLine(m.replyTo.Content, 200), 70)))
		b.WriteString("\n\n")
	} else {
		b.WriteString(titleStyle.Render("📝 New Post"))
		b.WriteString("\n\n")
	}
	b.WriteString(m.textInput.View())
	b.WriteString("\n\n")
	if m.posting {
		b.WriteString(menuStyle.Render(m.spinner.View() + " Publishing to your relays..."))
	} else {
		b.WriteString(menuStyle.Render("Press Enter to post"))
	}

	return b.String()
}

// parseRecipient accepts an npub or a 64-char hex public key.
func parseRecipient(s string) (string, error) {
	s = strings.TrimPrefix(strings.TrimSpace(s), "nostr:")
	if strings.HasPrefix(s, "npub") {
		if _, v, err := nip19.Decode(s); err == nil {
			if pk, ok := v.(string); ok {
				return pk, nil
			}
		}
		return "", fmt.Errorf("that npub isn't valid")
	}
	if pk := strings.ToLower(s); len(pk) == 64 && strings.Trim(pk, "0123456789abcdef") == "" {
		return pk, nil
	}
	return "", fmt.Errorf("enter an npub or a 64-character hex public key")
}
