package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// Screen represents the current view
type Screen int

const (
	ScreenLogin Screen = iota
	ScreenHome
	ScreenPost
	ScreenFeed
	ScreenTip
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

	// Feed state
	feedPosts   []FeedPost
	feedLoading bool
	feedScroll  int

	// Callbacks
	onLogin    func(nsec string, password string) (string, error) // returns pubkey
	onPost     func(message string) error
	onLoadKey  func(password string) (privateKey string, pubkey string, err error)
	onLoadFeed func() ([]FeedPost, error)
	hasKey     func() bool
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
	onLogin func(nsec string, password string) (string, error),
	onPost func(message string) error,
	onLoadFeed func() ([]FeedPost, error),
) {
	m.hasKey = hasKey
	m.onLoadKey = onLoadKey
	m.onLogin = onLogin
	m.onPost = onPost
	m.onLoadFeed = onLoadFeed
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
			if m.screen == ScreenFeed {
				if m.feedScroll < len(m.feedPosts)-4 {
					m.feedScroll++
				}
			} else {
				m.cursor++
			}
		}
	}

	// Update text input
	if m.screen == ScreenLogin || m.screen == ScreenPost || m.screen == ScreenTip {
		m.textInput, cmd = m.textInput.Update(msg)
	}

	return m, cmd
}

func (m Model) handleEnter() (tea.Model, tea.Cmd) {
	switch m.screen {
	case ScreenLogin:
		return m.handleLoginEnter()
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
		// User is entering nsec for first time
		if m.cursor == 0 {
			// New nsec entry
			nsec := m.textInput.Value()
			if nsec == "" || !strings.HasPrefix(nsec, "nsec") {
				m.message = "Please enter a valid nsec"
				m.messageStyle = errorStyle
				return m, nil
			}
			// Now we need password - switch to password mode
			m.textInput.Placeholder = "Create an encryption password..."
			m.textInput.EchoMode = textinput.EchoPassword
			m.textInput.Reset()
			m.message = "Now create a password to encrypt your key"
			m.messageStyle = inputStyle
			m.cursor = 1 // Mark that we're in password phase
		} else if m.cursor == 1 {
			// Password entry for new key
			password := m.textInput.Value()
			if password == "" {
				m.message = "Please enter a password"
				m.messageStyle = errorStyle
				return m, nil
			}
			// For now just move to home as placeholder
			m.loggedIn = true
			m.screen = ScreenHome
			m.message = "Logged in!"
			m.messageStyle = successStyle
			m.textInput.Reset()
			m.textInput.EchoMode = textinput.EchoNormal
		}
	}

	return m, nil
}

func (m Model) handleHomeEnter() (tea.Model, tea.Cmd) {
	switch m.cursor {
	case 0: // Post
		m.screen = ScreenPost
		m.textInput.Placeholder = "What's on your mind?"
		m.textInput.EchoMode = textinput.EchoNormal
		m.textInput.Reset()
		m.textInput.Focus()
		m.cursor = 0
	case 1: // Feed
		m.screen = ScreenFeed
		m.feedLoading = true
		m.feedPosts = nil
		m.feedScroll = 0
		// Load feed
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
	case 3: // Quit
		return m, tea.Quit
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
	case ScreenHome:
		b.WriteString(m.viewHome())
	case ScreenPost:
		b.WriteString(m.viewPost())
	case ScreenFeed:
		b.WriteString(m.viewFeed())
	case ScreenTip:
		b.WriteString(m.viewTip())
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
		b.WriteString("\n\n")
		m.textInput.Placeholder = "Password..."
		m.textInput.EchoMode = textinput.EchoPassword
	} else {
		b.WriteString(menuStyle.Render("Enter your Nostr private key (nsec) to get started:"))
		b.WriteString("\n\n")
	}

	b.WriteString(m.textInput.View())

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

// Config holds all the callbacks for TUI operations
type Config struct {
	HasKey     func() bool
	OnLoadKey  func(password string) (privateKey string, pubkey string, err error)
	OnLogin    func(nsec string, password string) (string, error)
	OnPost     func(message string) error
	OnLoadFeed func() ([]FeedPost, error)
}

// Run starts the TUI with the given configuration
func Run(cfg Config) error {
	m := NewModel()
	m.hasKey = cfg.HasKey
	m.onLoadKey = cfg.OnLoadKey
	m.onLogin = cfg.OnLogin
	m.onPost = cfg.OnPost
	m.onLoadFeed = cfg.OnLoadFeed
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
