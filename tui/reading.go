package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/nbd-wtf/go-nostr/nip19"
)

func (m Model) handleRepliesEnter() (tea.Model, tea.Cmd) {
	eventID := m.textInput.Value()
	if eventID == "" {
		m.message = "Please enter an event ID"
		m.messageStyle = errorStyle
		return m, nil
	}

	m.textInput.Reset()
	if m.onLoadReplies == nil {
		return m, nil
	}
	m.replyLoading = true
	m.replyPosts = nil
	m.message = ""
	load := m.onLoadReplies
	return m, m.startLoad(ScreenReplies, func() ([]FeedPost, error) { return load(eventID) })
}

// authorLabel is the display name for a post's author: their profile name
// if known, otherwise a shortened npub.
func authorLabel(p FeedPost) string {
	if p.AuthorName != "" {
		return p.AuthorName
	}
	if n := shortNpub(p.Author); n != "" {
		return n
	}
	return "unknown"
}

// truncateRunes shortens s to max runes (byte slicing could cut a
// multi-byte character in half).
func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}

const listPage = 4 // posts shown at once

// renderPostList draws up to listPage posts around the selected one, the
// selected post highlighted with its note1 ID underneath (for copying).
func renderPostList(b *strings.Builder, posts []FeedPost, sel int, noun string) {
	postStyle := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1).Width(64)
	selStyle := postStyle.BorderForeground(lipgloss.Color("205"))
	authorStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("205")).Bold(true)
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("241"))

	start := sel
	if start > len(posts)-listPage {
		start = len(posts) - listPage
	}
	if start < 0 {
		start = 0
	}
	end := start + listPage
	if end > len(posts) {
		end = len(posts)
	}
	for i := start; i < end; i++ {
		p := posts[i]
		header := authorStyle.Render(authorLabel(p)) + " " + dim.Render(p.CreatedAt)
		body := header + "\n" + truncateRunes(p.Content, 280)
		if i == sel {
			b.WriteString(selStyle.Render(body))
			b.WriteString("\n")
			if id := noteID(p.ID); id != "" {
				b.WriteString(dim.Render("  " + id))
				b.WriteString("\n")
			}
		} else {
			b.WriteString(postStyle.Render(body))
			b.WriteString("\n")
		}
	}
	if len(posts) > listPage {
		b.WriteString(menuStyle.Render(fmt.Sprintf("%d of %d %s", sel+1, len(posts), noun)))
		b.WriteString("\n")
	}
}

func (m Model) viewFeed() string {
	var b strings.Builder
	title := "📜 Global feed"
	if m.feedFollowing {
		title = "📜 Following"
	}
	b.WriteString(titleStyle.Render(title))
	b.WriteString("\n\n")

	switch {
	case m.feedLoading:
		b.WriteString(menuStyle.Render(m.spinner.View() + " Loading feed from your relays..."))
	case len(m.feedPosts) == 0:
		b.WriteString(menuStyle.Render("No posts yet."))
	default:
		renderPostList(&b, m.feedPosts, m.feedScroll, "posts")
	}
	b.WriteString("\n")
	other := "following"
	if m.feedFollowing {
		other = "global"
	}
	help := "↑/↓ select · Enter thread · r reply · + like · z zap"
	if m.onLoadFollowingFeed != nil {
		help += " · g " + other
	}
	b.WriteString(menuStyle.Render(help))
	return b.String()
}

func (m Model) viewDMs() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("🔒 Your Direct Messages"))
	b.WriteString("\n\n")

	switch {
	case m.dmLoading:
		b.WriteString(menuStyle.Render(m.spinner.View() + " Loading DMs from your relays..."))
	case len(m.dmPosts) == 0:
		b.WriteString(menuStyle.Render("No direct messages yet."))
	default:
		renderPostList(&b, m.dmPosts, m.dmScroll, "messages")
	}
	return b.String()
}

func (m Model) viewReplies() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("💬 Replies & Reactions"))
	b.WriteString("\n\n")

	if m.threadPost != nil {
		dim := lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
		b.WriteString(lipgloss.NewStyle().Bold(true).Render(authorLabel(*m.threadPost)) + " " + dim.Render(m.threadPost.CreatedAt))
		b.WriteString("\n")
		b.WriteString(truncateRunes(m.threadPost.Content, 400))
		b.WriteString("\n\n")
	}

	switch {
	case m.replyLoading:
		b.WriteString(menuStyle.Render(m.spinner.View() + " Loading replies from your relays..."))
		return b.String()
	case len(m.replyPosts) == 0 && m.threadPost != nil:
		b.WriteString(menuStyle.Render("No replies or reactions yet."))
	case len(m.replyPosts) > 0:
		renderPostList(&b, m.replyPosts, m.replyScroll, "replies & reactions")
	}

	b.WriteString("\n")
	if m.threadPost != nil {
		b.WriteString(menuStyle.Render("↑/↓ select · Enter open thread · r reply · + like · z zap · Esc back"))
		return b.String()
	}
	b.WriteString(menuStyle.Render("Enter an event ID (hex, note1… or nevent1…):"))
	b.WriteString("\n")
	b.WriteString(m.textInput.View())
	return b.String()
}

// noteID renders a hex event ID as note1…, or "" if it isn't one.
func noteID(hexID string) string {
	if hexID == "" {
		return ""
	}
	id, err := nip19.EncodeNote(hexID)
	if err != nil {
		return ""
	}
	return id
}
