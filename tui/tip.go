package tui

import (
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

func (m Model) viewTip() string {
	var b strings.Builder

	if m.zapPost != nil {
		b.WriteString(titleStyle.Render("⚡ Zap"))
		b.WriteString("\n")
		b.WriteString(menuStyle.Render(truncateRunes(oneLine(m.zapPost.Content, 200), 70)))
	} else {
		b.WriteString(titleStyle.Render("⚡ Tip Someone"))
	}
	b.WriteString("\n\n")
	switch {
	case m.tipping:
		b.WriteString(menuStyle.Render(m.spinner.View() + " Waiting for your wallet to pay..."))
	case m.tipStep == 1:
		b.WriteString(menuStyle.Render("To: " + m.tipTarget))
		b.WriteString("\n")
		b.WriteString(m.textInput.View())
		b.WriteString("\n\n")
		b.WriteString(menuStyle.Render("Enter the amount in sats"))
	default:
		b.WriteString(m.textInput.View())
		b.WriteString("\n\n")
		b.WriteString(menuStyle.Render("Enter a lightning address (name@domain), npub or hex pubkey"))
	}

	return b.String()
}

// tipResultMsg carries the outcome of a background tip payment.
type tipResultMsg struct {
	summary string
	err     error
}

// resetTipForm puts the tip screen back at the recipient step.
func (m *Model) resetTipForm() {
	m.tipStep = 0
	m.tipTarget = ""
	m.textInput.Placeholder = "name@domain, npub1... or hex pubkey"
	m.textInput.EchoMode = textinput.EchoNormal
	m.textInput.Reset()
	m.textInput.Focus()
}

func (m Model) handleTipEnter() (tea.Model, tea.Cmd) {
	if m.tipping {
		return m, nil
	}
	value := strings.TrimSpace(m.textInput.Value())

	if m.tipStep == 0 {
		if value == "" {
			m.message = "Enter who to tip"
			m.messageStyle = errorStyle
			return m, nil
		}
		m.tipTarget = value
		m.tipStep = 1
		m.message = ""
		m.textInput.Placeholder = "Amount in sats, e.g. 21"
		m.textInput.Reset()
		m.textInput.Focus()
		return m, nil
	}

	sats, err := strconv.ParseInt(strings.ReplaceAll(value, ",", ""), 10, 64)
	if err != nil || sats <= 0 {
		m.message = "Amount must be a whole number of sats greater than 0"
		m.messageStyle = errorStyle
		return m, nil
	}
	if m.zapPost != nil && m.onZap != nil {
		m.tipping = true
		m.message = ""
		zap, pk, id := m.onZap, m.zapPost.Author, m.zapPost.ID
		return m, func() tea.Msg {
			summary, err := zap(pk, id, sats)
			return tipResultMsg{summary: summary, err: err}
		}
	}
	if m.onTip == nil {
		m.message = "Tipping is not available"
		m.messageStyle = errorStyle
		return m, nil
	}

	m.tipping = true
	m.message = ""
	target, onTip := m.tipTarget, m.onTip
	return m, func() tea.Msg {
		summary, err := onTip(target, sats)
		return tipResultMsg{summary: summary, err: err}
	}
}
