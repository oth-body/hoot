package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/mdp/qrterminal/v3"
)

// Screen represents the current view
type Screen int

const (
	ScreenLogin Screen = iota
	ScreenQRLogin
	ScreenHome
	ScreenPost
	ScreenFeed
	ScreenTip
	ScreenRelays
)

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("205")).
			MarginBottom(1)

	menuStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("246"))

	selectedStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("205")).
			Bold(true)

	inputStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("86"))

	errorStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("196"))

	successStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("82"))
)

// FeedPost represents a single post in the feed
type FeedPost struct {
	Author    string
	Content   string
	CreatedAt string
}

// Model is the main TUI state
type Model struct {
	screen       Screen
	cursor       int
	textInput    textinput.Model
	message      string
	messageStyle lipgloss.Style

	// User state
	loggedIn   bool
	publicKey  string
	privateKey string

	// Temporary implementation of nsec storage during login flow
	tempNsec string

	// Feed state
	feedPosts   []FeedPost
	feedLoading bool
	feedScroll  int

	// QR Login State
	qrString string
	qrReady  bool

	// Relay State
	relays        []string
	addingRelay   bool // true if typing in new relay
	selectedRelay int  // index of selected relay

	// Callbacks
	onLogin      func(nsec string, password string, save bool) (string, error) // returns pubkey
	onPost       func(message string) error
	onLoadKey    func(password string) (privateKey string, pubkey string, err error)
	onResetKey   func() error
	onLoadFeed   func() ([]FeedPost, error)
	onInitQR     func() (string, error)
	onCheckQR    func() (string, error)
	onLoadRelays func() ([]string, error)
	onSaveRelays func(relays []string) error
	hasKey       func() bool
}

// NewModel creates a new TUI model
func NewModel() Model {
	ti := textinput.New()
	ti.Placeholder = "Enter your nsec..."
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 60

	return Model{
		screen:    ScreenLogin,
		textInput: ti,
	}
}

// SetCallbacks sets the callback functions
func (m *Model) SetCallbacks(
	hasKey func() bool,
	onLoadKey func(password string) (string, string, error),
	onResetKey func() error,
	onLogin func(nsec string, password string, save bool) (string, error),
	onPost func(message string) error,
	onLoadFeed func() ([]FeedPost, error),
	onInitQR func() (string, error),
	onCheckQR func() (string, error),
	onLoadRelays func() ([]string, error),
	onSaveRelays func(relays []string) error,
) {
	m.hasKey = hasKey
	m.onLoadKey = onLoadKey
	m.onResetKey = onResetKey
	m.onLogin = onLogin
	m.onPost = onPost
	m.onLoadFeed = onLoadFeed
	m.onInitQR = onInitQR
	m.onCheckQR = onCheckQR
	m.onLoadRelays = onLoadRelays
	m.onSaveRelays = onSaveRelays
}

func (m Model) Init() tea.Cmd {
	return textinput.Blink
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "esc":
			if m.screen == ScreenLogin {
				return m, tea.Quit
			}
			// Go back to home from other screens
			m.screen = ScreenHome
			m.message = ""
			return m, nil

		case "q":
			if m.screen == ScreenHome {
				return m, tea.Quit
			}

		case "r":
			if m.screen == ScreenLogin {
				hasKey := m.hasKey != nil && m.hasKey()
				if hasKey && m.onResetKey != nil {
					if err := m.onResetKey(); err != nil {
						m.message = fmt.Sprintf("Reset failed: %v", err)
						m.messageStyle = errorStyle
					} else {
						m.message = "Key file deleted. Please login again."
						m.messageStyle = successStyle
						m.textInput.Reset()
					}
					return m, nil
				}
			}

		case "enter":
			return m.handleEnter()

		case "up", "k":
			if m.screen == ScreenFeed {
				if m.feedScroll > 0 {
					m.feedScroll--
				}
			} else if m.cursor > 0 {
				m.cursor--
			}

		case "down", "j":
			switch m.screen {
			case ScreenFeed:
				if m.feedScroll < len(m.feedPosts)-4 {
					m.feedScroll++
				}
			case ScreenLogin:
				// Special handling for login menu
				hasKey := m.hasKey != nil && m.hasKey()
				limit := 0
				if !hasKey {
					limit = 1 // 0=Nsec, 1=QR
				}
				if m.cursor < limit {
					m.cursor++
				}
			default:
				m.cursor++
			}
		}

	case qrSuccessMsg:
		m.publicKey = string(msg)
		m.loggedIn = true
		m.screen = ScreenHome
		m.message = "Logged in via Amber!"
		m.messageStyle = successStyle
		return m, nil

	case qrGeneratedMsg:
		m.qrString = msg.uri
		m.qrReady = true
		// Start checking for connection in background
		return m, m.checkQRConnection
	}

	// Update text input
	if (m.screen == ScreenLogin && (m.cursor == 50 || m.cursor == 100)) || m.screen == ScreenPost || m.screen == ScreenTip || (m.screen == ScreenRelays && m.addingRelay) {
		// Only update input if we are in input mode (not menu selection mode)
		// For Login: if hasKey (Input mode) OR if !hasKey and cursor=0 (Nsec Entry? No, cursor 0 is menu choice)
		// Wait, if !hasKey:
		// Cursor 0 = "Enter nsec" MENU choice
		// Cursor 1 = "Scan QR" MENU Choice
		// Only when we select Cursor 0 do we enter INPUT mode.

		// I need to track if I'm in input mode vs menu mode better.
		// Previous logic used cursor=0 as input mode which overlapped with menu choice 0.
		// I'll stick to Previous Logic:
		// !hasKey: cursor 0, 1 are menu.
		// If user hits enter on 0, what happens?
		// See handleLoginEnter below.

		// Correct logic from before:
		// cursor 0 and !hasKey -> Menu Item 0
		// cursor 100 -> Input Mode for nsec?

		if m.screen == ScreenLogin {
			hasKey := m.hasKey != nil && m.hasKey()
			if hasKey {
				// Password input
				m.textInput, cmd = m.textInput.Update(msg)
			} else {
				// If cursor is 0 (Menu Item 1) -> No input
				// If cursor is 100 (Password Entry) -> Input
				// If cursor is 200 (Nsec Entry) -> Input (NEW STATE needed?)

				// Let's refine handleLoginEnter to handle the state transitions.
				// Here, we only update textinput if we are in a state that needs it.
				// If cursor == 100 (Password) or cursor == 0 AND we are in the "nsec entry" phase?
				// The previous code reused cursor=0 for menu. This is confusing.

				// Using cursor=50 for Nsec Entry, 100 for Password/Save choice.
				if m.cursor == 50 || m.cursor == 100 {
					m.textInput, cmd = m.textInput.Update(msg)
				}
			}
		} else {
			m.textInput, cmd = m.textInput.Update(msg)
		}
	}

	return m, cmd
}

func (m Model) handleEnter() (tea.Model, tea.Cmd) {
	switch m.screen {
	case ScreenLogin:
		return m.handleLoginEnter()
	case ScreenQRLogin:
		// Nothing to do on Enter, just wait or allow cancelling
		return m, nil
	case ScreenHome:
		return m.handleHomeEnter()
	case ScreenPost:
		return m.handlePostEnter()
	}
	return m, nil
}

func (m Model) handleLoginEnter() (tea.Model, tea.Cmd) {
	hasExistingKey := m.hasKey != nil && m.hasKey()

	if hasExistingKey {
		// User is entering password to unlock
		password := m.textInput.Value()
		if password == "" {
			m.message = "Please enter your password"
			m.messageStyle = errorStyle
			return m, nil
		}

		if m.onLoadKey != nil {
			privKey, pubKey, err := m.onLoadKey(password)
			if err != nil {
				m.message = fmt.Sprintf("Login failed: %v", err)
				m.messageStyle = errorStyle
				return m, nil
			}
			m.privateKey = privKey
			m.publicKey = pubKey
			m.loggedIn = true
			m.screen = ScreenHome
			m.message = ""
			m.textInput.Reset()
		}
	} else {
		// No existing key logic
		switch m.cursor {
		case 0:
			// "Enter Nostr private key" selected
			m.cursor = 50 // Switch to Nsec Entry Mode
			m.textInput.Placeholder = "nsec1..."
			m.textInput.EchoMode = textinput.EchoNormal
			m.textInput.Reset()
			m.textInput.Focus()

		case 50:
			// Nsec entered
			nsec := m.textInput.Value()
			if nsec == "" || !strings.HasPrefix(nsec, "nsec") {
				m.message = "Please enter a valid nsec"
				m.messageStyle = errorStyle
				return m, nil
			}
			m.tempNsec = nsec

			// Move to password creation (optional)
			m.cursor = 100
			m.textInput.Placeholder = "Enter password to save (or empty for ephemeral)"
			m.textInput.EchoMode = textinput.EchoPassword
			m.textInput.Reset()
			m.message = "Enter password to encrypt & save key, or press Enter to skip saving."
			m.messageStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("243")) // Gray

		case 100:
			// Password phase
			password := m.textInput.Value()
			save := password != ""

			if m.onLogin != nil {
				pubKey, err := m.onLogin(m.tempNsec, password, save)
				if err != nil {
					m.message = fmt.Sprintf("Login failed: %v", err)
					m.messageStyle = errorStyle
					m.cursor = 0 // Reset to menu
					return m, nil
				}
				m.publicKey = pubKey
			}
			m.loggedIn = true
			m.screen = ScreenHome
			m.message = "Logged in!"
			if !save {
				m.message += " (Ephemeral Session)"
			}
			m.messageStyle = successStyle

		case 1:
			// QR Code Login selected
			m.screen = ScreenQRLogin
			m.qrReady = false
			m.message = "Generating QR code..."
			return m, m.initQR
		}
	}

	return m, nil
}

type qrSuccessMsg string

func (m Model) initQR() tea.Msg {
	if m.onInitQR != nil {
		uri, err := m.onInitQR()
		if err != nil {
			return nil
		}
		var sb strings.Builder
		config := qrterminal.Config{
			Level:     qrterminal.M,
			Writer:    &sb,
			BlackChar: qrterminal.BLACK,
			WhiteChar: qrterminal.WHITE,
			QuietZone: 1,
		}
		qrterminal.GenerateWithConfig(uri, config)
		return qrGeneratedMsg{uri: sb.String()}
	}
	return nil
}

type qrGeneratedMsg struct {
	uri string
}

func (m Model) checkQRConnection() tea.Msg {
	if m.onCheckQR != nil {
		pubkey, err := m.onCheckQR()
		if err == nil && pubkey != "" {
			return qrSuccessMsg(pubkey)
		}
	}
	return nil
}

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
		m.feedLoading = true
		m.feedPosts = nil
		m.feedScroll = 0
		if m.onLoadFeed != nil {
			posts, err := m.onLoadFeed()
			if err != nil {
				m.message = fmt.Sprintf("Failed to load feed: %v", err)
				m.messageStyle = errorStyle
			} else {
				m.feedPosts = posts
			}
			m.feedLoading = false
		}
	case 2: // Tip
		m.screen = ScreenTip
		m.textInput.Placeholder = "Enter npub or lightning address..."
		m.textInput.Reset()
		m.textInput.Focus()
	case 3: // Relays
		m.screen = ScreenRelays
		m.addingRelay = false
		m.selectedRelay = 0
		if m.onLoadRelays != nil {
			relays, err := m.onLoadRelays()
			if err == nil {
				m.relays = relays
			}
		}
	case 4: // Quit
		return m, tea.Quit
	}
	return m, nil
}

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
				m.onSaveRelays(m.relays)
			}
			m.message = "Relay added"
			m.messageStyle = successStyle
		}
		m.addingRelay = false
		m.textInput.Reset()
	} else {
		// Toggle add mode?
		// Or maybe Enter on "Add Relay" button?
		// Simplify: 'a' to add, 'd' to delete.
		// Enter does nothing unless we have a menu.
	}
	return m, nil
}

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

func (m Model) View() string {
	var b strings.Builder

	switch m.screen {
	case ScreenLogin:
		b.WriteString(m.viewLogin())
	case ScreenQRLogin:
		b.WriteString(m.viewQRLogin())
	case ScreenHome:
		b.WriteString(m.viewHome())
	case ScreenPost:
		b.WriteString(m.viewPost())
	case ScreenFeed:
		b.WriteString(m.viewFeed())
	case ScreenTip:

		b.WriteString(m.viewTip())
	case ScreenRelays:
		b.WriteString(m.viewRelays())
	}

	if m.message != "" {
		b.WriteString("\n" + m.messageStyle.Render(m.message))
	}

	b.WriteString("\n\n" + menuStyle.Render("Press Esc to go back, Ctrl+C to quit"))

	return b.String()
}

func (m Model) viewLogin() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("🦉 Welcome to Hoot!"))
	b.WriteString("\n\n")

	hasExistingKey := m.hasKey != nil && m.hasKey()

	if hasExistingKey {
		b.WriteString(menuStyle.Render("Enter your password to unlock:"))
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("(Or press 'r' to reset/delete key)"))
		b.WriteString("\n\n")
		m.textInput.Placeholder = "Password..."
		m.textInput.EchoMode = textinput.EchoPassword
		b.WriteString(m.textInput.View())
	} else {
		// No key scenarios
		if m.cursor == 50 {
			b.WriteString(menuStyle.Render("Enter your Nostr private key (nsec):"))
			b.WriteString("\n\n")
			b.WriteString(m.textInput.View())
		} else if m.cursor == 100 {
			b.WriteString(menuStyle.Render("Secure your key with a password:"))
			b.WriteString("\n")
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("(Leave empty to use ephemeral session without saving)"))
			b.WriteString("\n\n")
			b.WriteString(m.textInput.View())
		} else {
			b.WriteString(menuStyle.Render("Choose login method:"))
			b.WriteString("\n\n")

			options := []string{
				"Enter Nostr private key (nsec)",
				"Scan QR with Amber (NIP-46)",
			}

			for i, opt := range options {
				if i == m.cursor {
					b.WriteString(selectedStyle.Render(fmt.Sprintf("→ %s", opt)))
				} else {
					b.WriteString(menuStyle.Render(fmt.Sprintf("  %s", opt)))
				}
				b.WriteString("\n")
			}
		}
	}

	return b.String()
}

func (m Model) viewQRLogin() string {
	var b strings.Builder
	b.WriteString(titleStyle.Render("📱 Scan with Amber"))
	b.WriteString("\n\n")

	if m.qrString != "" {
		b.WriteString(m.qrString)
		b.WriteString("\n\n")
		b.WriteString(menuStyle.Render("Waiting for connection... scan this with your Amber app."))
	} else {
		b.WriteString(menuStyle.Render("Generating connection..."))
	}

	return b.String()
}

func (m Model) viewHome() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("🦉 Hoot"))
	if m.publicKey != "" {
		b.WriteString(menuStyle.Render(fmt.Sprintf(" - %s...", m.publicKey[:16])))
	}
	b.WriteString("\n\n")

	menuItems := []string{
		"[p] Post a message",
		"[f] View feed",

		"[t] Tip someone",
		"[r] Manage Relays",
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

func (m Model) viewPost() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("📝 New Post"))
	b.WriteString("\n\n")
	b.WriteString(m.textInput.View())
	b.WriteString("\n\n")
	b.WriteString(menuStyle.Render("Press Enter to post"))

	return b.String()
}

func (m Model) viewFeed() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("📜 Your Feed"))
	b.WriteString("\n\n")

	if m.feedLoading {
		b.WriteString(menuStyle.Render("Loading..."))
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

func (m Model) viewTip() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("⚡ Tip Someone"))
	b.WriteString("\n\n")
	b.WriteString(m.textInput.View())
	b.WriteString("\n\n")
	b.WriteString(menuStyle.Render("Enter npub or lightning address, then amount"))

	return b.String()
}

func (m Model) viewRelays() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("🔗 Relay Settings"))
	b.WriteString("\n\n")

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
		b.WriteString(menuStyle.Render("[a] Add Relay  [d] Delete Selected  [esc] Back"))
	}

	return b.String()
}

// Config holds all the callbacks for TUI operations
type Config struct {
	HasKey       func() bool
	OnLoadKey    func(password string) (privateKey string, pubkey string, err error)
	OnResetKey   func() error
	OnLogin      func(nsec string, password string, save bool) (string, error)
	OnPost       func(message string) error
	OnLoadFeed   func() ([]FeedPost, error)
	OnInitQR     func() (string, error)
	OnCheckQR    func() (string, error)
	OnLoadRelays func() ([]string, error)
	OnSaveRelays func(relays []string) error
}

// Run starts the TUI with the given configuration
func Run(cfg Config) error {
	m := NewModel()
	m.hasKey = cfg.HasKey
	m.onLoadKey = cfg.OnLoadKey
	m.onResetKey = cfg.OnResetKey
	m.onLogin = cfg.OnLogin
	m.onPost = cfg.OnPost
	m.onLoadFeed = cfg.OnLoadFeed
	m.onInitQR = cfg.OnInitQR
	m.onCheckQR = cfg.OnCheckQR
	m.onLoadRelays = cfg.OnLoadRelays
	m.onSaveRelays = cfg.OnSaveRelays
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
