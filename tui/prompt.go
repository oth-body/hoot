package tui

import "github.com/charmbracelet/bubbles/textinput"

// All screens share one text field. Every prompt must open it through
// openPrompt or openSecretPrompt, which reset the echo mode: a prompt that
// set only its placeholder inherited the login form's password mode, so
// replies showed ***** after signing in. TestPromptsOnlyOpenThroughHelper
// enforces this.

// openPrompt shows an empty, focused field that displays what you type.
func (m *Model) openPrompt(placeholder string) {
	m.setPrompt(placeholder, false)
}

// openSecretPrompt shows an empty, focused, masked field (passwords, nsec).
// Ctrl+R toggles showing the text while it's open.
func (m *Model) openSecretPrompt(placeholder string) {
	m.setPrompt(placeholder, true)
}

func (m *Model) setPrompt(placeholder string, secret bool) {
	m.textInput.Placeholder = placeholder
	m.textInput.EchoMode = textinput.EchoNormal
	if secret {
		m.textInput.EchoMode = textinput.EchoPassword
	}
	m.secretPrompt = secret
	m.textInput.Reset()
	m.textInput.Focus()
}

// toggleReveal flips a secret prompt between masked and visible.
func (m *Model) toggleReveal() bool {
	if !m.secretPrompt {
		return false
	}
	if m.textInput.EchoMode == textinput.EchoPassword {
		m.textInput.EchoMode = textinput.EchoNormal
	} else {
		m.textInput.EchoMode = textinput.EchoPassword
	}
	return true
}

// revealHint is shown under secret prompts.
func (m Model) revealHint() string {
	if m.textInput.EchoMode == textinput.EchoPassword {
		return "Ctrl+R to show what you typed"
	}
	return "Ctrl+R to hide it again"
}
