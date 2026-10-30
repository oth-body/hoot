package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

func (m Model) handleRelaysEnter() (tea.Model, tea.Cmd) {
	if m.addingRelay {
		// Save new relay
		newRelay := m.textInput.Value()
		if newRelay != "" {
			if !strings.HasPrefix(newRelay, "wss://") && !strings.HasPrefix(newRelay, "ws://") {
				newRelay = "wss://" + newRelay
			}
			m.relays = append(m.relays, newRelay)
			if m.onSaveRelays != nil {
				if err := m.onSaveRelays(m.relays); err != nil {
					m.message = fmt.Sprintf("Failed to save relay: %v", err)
					m.messageStyle = errorStyle
					m.addingRelay = false
					m.textInput.Reset()
					return m, nil
				}
			}
			m.message = "Relay added"
			m.messageStyle = successStyle
		}
		m.addingRelay = false
		m.textInput.Reset()
	}
	// Enter does nothing while browsing the list — 'a' adds, 'd' deletes.
	return m, nil
}

func (m Model) viewRelays() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("🔗 Relay Settings"))
	b.WriteString("\n\n")

	if !m.loggedIn {
		b.WriteString(menuStyle.Render("Choose which relays hoot uses to publish, read, and pair via QR."))
		b.WriteString("\n\n")
	}

	if m.addingRelay {
		b.WriteString(menuStyle.Render("Enter new relay URL:"))
		b.WriteString("\n")
		b.WriteString(m.textInput.View())
		b.WriteString("\n")
		b.WriteString(menuStyle.Render("(Press Enter to save, Esc to cancel)"))
	} else {
		if len(m.relays) == 0 {
			b.WriteString(menuStyle.Render("No relays configured."))
		} else {
			for i, r := range m.relays {
				prefix := "  "
				if i == m.selectedRelay {
					prefix = "→ "
				}
				b.WriteString(prefix + r + "\n")
			}
		}
		b.WriteString("\n")
		backLabel := "Back to Home"
		if !m.loggedIn {
			backLabel = "Back to Login"
		}
		b.WriteString(menuStyle.Render(fmt.Sprintf("[a] Add Relay  [d] Delete Selected  [esc] %s", backLabel)))
	}

	return b.String()
}
