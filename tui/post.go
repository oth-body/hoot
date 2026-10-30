package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func (m Model) handlePostEnter() (tea.Model, tea.Cmd) {
	content := m.textInput.Value()
	if content == "" {
		m.message = "Message cannot be empty"
		m.messageStyle = errorStyle
		return m, nil
	}

	if m.posting || m.onPost == nil {
		return m, nil
	}
	m.posting = true
	m.message = ""
	post := m.onPost
	return m, func() tea.Msg { return postedMsg{err: post(content)} }
}

func (m Model) viewPost() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("📝 New Post"))
	b.WriteString("\n\n")
	b.WriteString(m.textInput.View())
	b.WriteString("\n\n")
	if m.posting {
		b.WriteString(menuStyle.Render(m.spinner.View() + " Publishing to your relays..."))
	} else {
		b.WriteString(menuStyle.Render("Press Enter to post"))
	}

	return b.String()
}
