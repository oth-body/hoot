package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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

func (m Model) viewFeed() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("📜 Your Feed"))
	b.WriteString("\n\n")

	if m.feedLoading {
		b.WriteString(menuStyle.Render(m.spinner.View() + " Loading feed from your relays..."))
		return b.String()
	}

	if len(m.feedPosts) == 0 {
		b.WriteString(menuStyle.Render("No posts yet."))
		return b.String()
	}

	postStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(0, 1).
		MarginBottom(1).
		Width(60)

	authorStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("205")).
		Bold(true)

	timeStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241"))

	// Show up to 4 posts based on scroll
	start := m.feedScroll
	end := start + 4
	if end > len(m.feedPosts) {
		end = len(m.feedPosts)
	}

	for _, post := range m.feedPosts[start:end] {
		authorDisplay := post.Author
		if len(authorDisplay) > 16 {
			authorDisplay = authorDisplay[:16] + "..."
		}
		header := authorStyle.Render(authorDisplay) + " " + timeStyle.Render(post.CreatedAt)
		content := post.Content
		if len(content) > 200 {
			content = content[:200] + "..."
		}
		b.WriteString(postStyle.Render(header + "\n" + content))
		b.WriteString("\n")
	}

	if len(m.feedPosts) > 4 {
		b.WriteString(menuStyle.Render(fmt.Sprintf("Showing %d-%d of %d posts (↑/↓ to scroll)", start+1, end, len(m.feedPosts))))
	}

	return b.String()
}

func (m Model) viewDMs() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("🔒 Your Direct Messages"))
	b.WriteString("\n\n")

	if m.dmLoading {
		b.WriteString(menuStyle.Render(m.spinner.View() + " Loading DMs from your relays..."))
		return b.String()
	}

	if len(m.dmPosts) == 0 {
		b.WriteString(menuStyle.Render("No direct messages yet."))
		return b.String()
	}

	postStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(0, 1).
		MarginBottom(1).
		Width(60)

	authorStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("205")).
		Bold(true)

	timeStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241"))

	// Show up to 4 posts based on scroll
	start := m.dmScroll
	end := start + 4
	if end > len(m.dmPosts) {
		end = len(m.dmPosts)
	}

	for _, post := range m.dmPosts[start:end] {
		authorDisplay := post.Author
		if len(authorDisplay) > 16 {
			authorDisplay = authorDisplay[:16] + "..."
		}
		header := authorStyle.Render(authorDisplay) + " " + timeStyle.Render(post.CreatedAt)
		content := post.Content
		if len(content) > 200 {
			content = content[:200] + "..."
		}
		b.WriteString(postStyle.Render(header + "\n" + content))
		b.WriteString("\n")
	}

	if len(m.dmPosts) > 4 {
		b.WriteString(menuStyle.Render(fmt.Sprintf("Showing %d-%d of %d messages (↑/↓ to scroll)", start+1, end, len(m.dmPosts))))
	}

	return b.String()
}

func (m Model) viewReplies() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("💬 Replies & Reactions"))
	b.WriteString("\n\n")

	if m.replyLoading {
		b.WriteString(menuStyle.Render(m.spinner.View() + " Loading replies from your relays..."))
		return b.String()
	}

	if len(m.replyPosts) == 0 {
		b.WriteString(menuStyle.Render("Enter an event ID to view replies/reactions"))
		b.WriteString("\n\n")
		b.WriteString(m.textInput.View())
		return b.String()
	}

	postStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		Padding(0, 1).
		MarginBottom(1).
		Width(60)

	authorStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("205")).
		Bold(true)

	timeStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241"))

	// Show up to 4 posts based on scroll
	start := m.replyScroll
	end := start + 4
	if end > len(m.replyPosts) {
		end = len(m.replyPosts)
	}

	for _, post := range m.replyPosts[start:end] {
		authorDisplay := post.Author
		if len(authorDisplay) > 16 {
			authorDisplay = authorDisplay[:16] + "..."
		}
		header := authorStyle.Render(authorDisplay) + " " + timeStyle.Render(post.CreatedAt)
		content := post.Content
		if len(content) > 200 {
			content = content[:200] + "..."
		}
		b.WriteString(postStyle.Render(header + "\n" + content))
		b.WriteString("\n")
	}

	if len(m.replyPosts) > 4 {
		b.WriteString(menuStyle.Render(fmt.Sprintf("Showing %d-%d of %d replies (↑/↓ to scroll)", start+1, end, len(m.replyPosts))))
	}
	b.WriteString("\n")
	b.WriteString(menuStyle.Render("[Enter new event ID to view more replies]"))
	b.WriteString("\n")
	b.WriteString(m.textInput.View())

	return b.String()
}
