package tui

import (
	"hoot/nip46"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mdp/qrterminal/v3"
	"github.com/muesli/reflow/ansi"
)

type qrSuccessMsg struct {
	pubkey  string
	profile *nip46.ProfileMetadata // may be nil if kind-0 fetch failed
}

type qrInitErrorMsg struct {
	err error
}

func (m Model) initQR() tea.Msg {
	if m.onInitQR != nil {
		uri, err := m.onInitQR()
		if err != nil {
			// Previously this returned nil and the error was
			// silently swallowed — the user saw the QR screen
			// forever with "Generating connection..." and no
			// clue what to fix. Surface the error so viewQRLogin
			// can render an actionable message instead.
			return qrInitErrorMsg{err: err}
		}
		return qrGeneratedMsg{uri: uri}
	}
	return nil
}

// regenerateQR generates the QR code based on current terminal dimensions.
//
// If the terminal is too small (or dimensions haven't been measured yet),
// the qrRendered buffer is cleared and the qrNeedsRegeneration flag is left
// set so the QR will be regenerated on the next View() call. Without this,
// an early-return would permanently stick the flag in a "needs regen" state
// that never fires again — which was the source of the original bug where
// the QR code failed to render when qrGeneratedMsg arrived before
// tea.WindowSizeMsg.
func (m *Model) regenerateQR() {
	if m.qrData == "" {
		m.qrRendered = ""
		m.qrNeedsRegeneration = false
		return
	}

	if m.width < 20 || m.height < 10 {
		// Terminal too small to render a useful QR — keep the regen
		// flag set so we try again as soon as the dimensions change.
		m.qrRendered = ""
		return
	}

	var sb strings.Builder

	// Adjust configuration based on available space.
	//
	// Use half-block rendering by default — it packs two QR rows into
	// each terminal line (half the height), which is the only practical
	// way to fit a real-world nostr URI (150–300 bytes) into a typical
	// terminal. Don't pass BlackChar/WhiteChar; qrterminal's defaults
	// are the half-block Unicode glyphs (▀▄█ space). Overriding them
	// with the ANSI-bg constants (qrterminal.BLACK/WHITE, which are
	// 6-byte escape sequences per module) inflates each module to 6
	// terminal columns in half-block mode, blowing the QR out to 300+
	// columns wide and overflowing any reasonable terminal.
	config := qrterminal.Config{
		Level:      qrterminal.L, // Lower error correction for smaller QR
		Writer:     &sb,
		HalfBlocks: true,
		QuietZone:  1, // 1-module border; qrterminal enforces a minimum of 1
	}

	qrterminal.GenerateWithConfig(m.qrData, config)
	m.qrRendered = sb.String()
	m.qrNeedsRegeneration = false
}

type qrGeneratedMsg struct {
	uri string
}

func (m Model) checkQRConnection() tea.Msg {
	if m.onCheckQR != nil {
		pubkey, profile, err := m.onCheckQR()
		if err == nil && pubkey != "" {
			return qrSuccessMsg{pubkey: pubkey, profile: profile}
		}
		if err != nil && !nip46.IsRetryable(err) {
			// Hard failure (proxy refusal, zero relays connected,
			// all subscriptions dropped, etc.). Don't keep retrying
			// — show the user the actionable message via the same
			// error path as qrInitErrorMsg.
			return qrInitErrorMsg{err: err}
		}
		// Transient (ErrTimeout with Open > 0, deadline, cancel).
		// Re-fire after a short delay so we keep polling without
		// blocking the TUI render loop. tea.Tick fires a callback
		// after the duration that returns the Cmd to execute.
		return qrRetryMsg{}
	}
	return nil
}

// qrRetryMsg signals that the QR connection check should be
// retried after a short delay.
type qrRetryMsg struct{}

// checkQRTickMsg is fired by tea.Tick after the retry delay,
// triggering another checkQRConnection round.
type checkQRTickMsg struct{}

func (m Model) viewQRLogin() string {
	// Build the screen as a single block: title, body, footer. The
	// outer View() centers this block inside the terminal using
	// lipgloss.Place, which right-pads every line to the block's
	// widest line via ansi.PrintableRuneWidth. If individual lines
	// differ in printable width, lipgloss leaves them at different
	// indents (each line is centered on its own width). To keep
	// every line visually "together" — title, QR, and footers all
	// at the same column — we explicitly right-pad every line so
	// each line reports the same printable width to lipgloss.
	var body strings.Builder

	// Title (right-padded below).
	title := titleStyle.Render("📱 Scan with Amber")

	var middle string
	var suffix string
	if m.qrRendered != "" {
		// QR is rendered. Don't append the global m.message here —
		// it could be the leftover "Generating QR code..." string
		// from handleLoginEnter, which was cleared in the
		// qrGeneratedMsg handler. Showing it below the QR would
		// contradict the QR that's on-screen.
		middle = m.qrRendered
		suffix = menuStyle.Render("Waiting for connection... scan this with your Amber app.")
	} else if m.qrData != "" {
		middle = m.spinner.View() + " Generating QR code..."
		suffix = ""
	} else {
		middle = m.spinner.View() + " Generating connection..."
		suffix = ""
	}

	// Find the QR's max ansi-printable width so we can right-pad
	// every line to it. Use ansi.PrintableRuneWidth so the count
	// matches what lipgloss will see in PlaceHorizontal — using
	// runewidth.StringWidth would count double-width emoji as
	// 2 cols and create a 1-col mismatch that breaks alignment.
	qrWidth := 0
	for _, l := range strings.Split(middle, "\n") {
		if w := ansi.PrintableRuneWidth(l); w > qrWidth {
			qrWidth = w
		}
	}
	if suffix != "" {
		if w := ansi.PrintableRuneWidth(suffix); w > qrWidth {
			qrWidth = w
		}
	}
	// Include the "Press Esc" global footer in the same block so the
	// whole screen — including the global footer — is centered as one
	// unit. Without this, View()'s trailing footer would sit at a
	// different column than the title/QR group.
	footer := menuStyle.Render("Press Esc to go back, Ctrl+C to quit")
	if w := ansi.PrintableRuneWidth(footer); w > qrWidth {
		qrWidth = w
	}

	padLine := func(s string) string {
		w := ansi.PrintableRuneWidth(s)
		if w >= qrWidth {
			return s
		}
		return s + strings.Repeat(" ", qrWidth-w)
	}

	body.WriteString(padLine(title))
	body.WriteString("\n\n")
	for _, l := range strings.Split(middle, "\n") {
		body.WriteString(padLine(l))
		body.WriteString("\n")
	}
	if suffix != "" {
		body.WriteString(padLine(suffix))
		body.WriteString("\n")
	}
	body.WriteString(padLine(footer))

	return body.String()
}
