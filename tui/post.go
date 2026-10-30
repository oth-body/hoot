package tui

import (
	"fmt"
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

	if m.onPost != nil {
		err := m.onPost(content)
		if err != nil {
			m.message = fmt.Sprintf("Failed to post: %v", err)
			m.messageStyle = errorStyle
			return m, nil
		}
	}

	m.message = "Posted successfully!"
	m.messageStyle = successStyle
	m.textInput.Reset()
	m.screen = ScreenHome
	m.cursor = 0
	return m, nil
}

func (m Model) viewPost() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("📝 New Post"))
	b.WriteString("\n\n")
	b.WriteString(m.textInput.View())
	b.WriteString("\n\n")
	b.WriteString(menuStyle.Render("Press Enter to post"))

	return b.String()
}
