package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/reflow/ansi"

	"hoot/nip46"
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
	ScreenDMs     // New screen for direct messages
	ScreenReplies // New screen for replies/reactions
	ScreenTip
	ScreenRelays
	ScreenProfiles // New screen for profile management
)

// Styles
var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("205"))

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

// ProfileInfo represents a profile for display in the TUI
type ProfileInfo struct {
	ID        string
	Name      string
	PublicKey string
}

// Model is the main TUI state
type Model struct {
	screen       Screen
	cursor       int
	textInput    textinput.Model
	spinner      spinner.Model
	message      string
	messageStyle lipgloss.Style

	// Terminal size for centering
	width  int
	height int

	// User state
	loggedIn   bool
	publicKey  string
	privateKey string

	// Temporary implementation of nsec storage during login flow
	tempNsec string
	tempName string // profile name during creation

	// Profile state
	profiles            []ProfileInfo
	selectedProfile     int    // index in profile list
	currentProfileID    string // ID of logged-in profile
	currentProfileName  string // display name (from kind-0 metadata if Amber login, otherwise user-set name)
	currentProfileAbout string // "about" line from kind-0 metadata (Amber login only)
	currentProfileNIP05 string // NIP-05 identifier from kind-0 metadata (Amber login only)
	lastUsedProfileID   string
	addingProfile       bool // true when creating new profile

	// Feed state
	feedPosts   []FeedPost
	feedLoading bool
	feedScroll  int

	// DMs state
	dmPosts   []FeedPost
	dmLoading bool
	dmScroll  int

	// Replies state
	replyPosts   []FeedPost
	replyLoading bool
	replyScroll  int

	// QR Login State
	qrData              string // Store URI instead of rendered string
	qrRendered          string // Generated QR code based on current dimensions
	qrReady             bool
	qrNeedsRegeneration bool // Flag to regenerate on resize

	// Relay State
	relays        []string
	addingRelay   bool // true if typing in new relay
	selectedRelay int  // index of selected relay

	// Callbacks
	onLogin       func(nsec string, password string, save bool) (string, error) // returns pubkey
	onPost        func(message string) error
	onLoadKey     func(password string) (privateKey string, pubkey string, err error)
	onResetKey    func() error
	onLoadFeed    func() ([]FeedPost, error)
	onLoadDMs     func(privateKey string) ([]FeedPost, error)
	onLoadReplies func(eventID string) ([]FeedPost, error)
	onInitQR      func() (string, error)
	onCheckQR     func() (string, *nip46.ProfileMetadata, error)
	onLoadRelays  func() ([]string, error)
	onSaveRelays  func(relays []string) error
	hasKey        func() bool

	// Profile callbacks
	onListProfiles  func() ([]ProfileInfo, string, error) // returns profiles + lastUsedID
	onSelectProfile func(id, password string) (privKey, pubKey string, err error)
	onAddProfile    func(name, nsec, password string) (pubKey string, err error)
	onDeleteProfile func(id string) error
}

// NewModel creates a new TUI model
func NewModel() Model {
	ti := textinput.New()
	ti.Placeholder = "Enter your nsec..."
	ti.Focus()
	ti.CharLimit = 256
	ti.Width = 60

	// Spinner used while waiting on QR init / remote-signer connection.
	// The Line frame set is plain ASCII so the indicator renders even on
	// terminals without Unicode support.
	sp := spinner.New(spinner.WithSpinner(spinner.Line))

	return Model{
		screen:    ScreenLogin,
		textInput: ti,
		spinner:   sp,
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
	onCheckQR func() (string, *nip46.ProfileMetadata, error),
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
	return tea.Batch(textinput.Blink, m.spinner.Tick)
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	// Spinner animation tick. The spinner.Model owns its own state and
	// returns the next TickMsg as a tea.Cmd that we batch below.
	var spinnerCmd tea.Cmd
	m.spinner, spinnerCmd = m.spinner.Update(msg)

	// Check if we need to regenerate the QR code
	if m.qrNeedsRegeneration && m.qrData != "" {
		m.regenerateQR()
	}

	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		widthChanged := m.width != msg.Width
		heightChanged := m.height != msg.Height
		m.width = msg.Width
		m.height = msg.Height

		// If window dimensions changed and we have QR data, force a
		// regeneration. We call regenerateQR directly (rather than only
		// setting the flag) so the new dimensions are applied even when
		// the previous Update already attempted a regen with stale zeros.
		if (widthChanged || heightChanged) && m.qrData != "" {
			m.qrNeedsRegeneration = true
			m.regenerateQR()
		}

		return m, nil

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
			switch m.screen {
			case ScreenFeed:
				if m.feedScroll > 0 {
					m.feedScroll--
				}
			case ScreenDMs:
				if m.dmScroll > 0 {
					m.dmScroll--
				}
			case ScreenReplies:
				if m.replyScroll > 0 {
					m.replyScroll--
				}
			default:
				if m.cursor > 0 {
					m.cursor--
				}
			}

		case "down", "j":
			switch m.screen {
			case ScreenFeed:
				if m.feedScroll < len(m.feedPosts)-4 {
					m.feedScroll++
				}
			case ScreenDMs:
				if m.dmScroll < len(m.dmPosts)-4 {
					m.dmScroll++
				}
			case ScreenReplies:
				if m.replyScroll < len(m.replyPosts)-4 {
					m.replyScroll++
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
			case ScreenHome:
				if m.cursor < 7 {
					m.cursor++
				}
			default:
				m.cursor++
			}
		}

	case qrSuccessMsg:
		m.publicKey = msg.pubkey
		m.loggedIn = true
		m.screen = ScreenHome
		// Surface the kind-0 profile on the home screen. The
		// signer-published name wins over the raw pubkey prefix
		// because users recognise themselves by name, not by
		// 16 hex chars. If the kind-0 fetch failed (msg.profile
		// is nil — many users haven't set a profile), fall back
		// to a friendly "Logged in" message and let viewHome
		// render the npub.
		if msg.profile != nil && msg.profile.Name != "" {
			m.currentProfileName = msg.profile.Name
			m.message = fmt.Sprintf("Logged in as %s", msg.profile.Name)
		} else {
			m.message = "Logged in via Amber!"
		}
		if msg.profile != nil {
			m.currentProfileAbout = msg.profile.About
			m.currentProfileNIP05 = msg.profile.NIP05
		}
		m.messageStyle = successStyle
		return m, nil

	case qrGeneratedMsg:
		m.qrData = msg.uri
		m.qrNeedsRegeneration = true
		m.qrReady = true
		// Clear the "Generating QR code..." banner left over from
		// handleLoginEnter — the QR is now visible, so showing that
		// text below it is contradictory and read by users as "stuck".
		m.message = ""
		m.messageStyle = lipgloss.Style{}
		// Start checking for connection in background
		return m, m.checkQRConnection

	case qrInitErrorMsg:
		// OnInitQR failed (proxy env var set, all relays unreachable,
		// bad relays.txt, etc.). Surface the actionable error from
		// nip46.go instead of leaving "Generating connection..."
		// on screen forever. Stay on ScreenQRLogin so the user can
		// press Esc to back out; the message goes into m.message so
		// viewQRLogin will pick it up at the bottom of the block.
		m.qrReady = false
		m.message = fmt.Sprintf("Sign-in failed: %v", msg.err)
		m.messageStyle = errorStyle
		return m, nil

	case qrRetryMsg:
		// The previous check didn't find a signer connect event yet.
		// Re-fire after a short delay so we keep polling without
		// blocking the TUI render loop. tea.Tick fires a callback
		// after the duration that returns the Cmd to execute.
		return m, tea.Tick(time.Second, func(t time.Time) tea.Msg {
			return checkQRTickMsg{}
		})

	case checkQRTickMsg:
		// Fired by the retry timer above — run another check.
		return m, m.checkQRConnection
	}

	// Update text input
	if (m.screen == ScreenLogin && (m.cursor == 50 || m.cursor == 51 || m.cursor == 100 || m.cursor == 200)) || m.screen == ScreenPost || m.screen == ScreenTip || m.screen == ScreenReplies || (m.screen == ScreenRelays && m.addingRelay) {
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

				// Let's refine handleLoginEnter to handle state transitions.
				// Here, we only update textinput if we are in a state that needs it.
				// If cursor == 100 (Password) or cursor == 0 AND we are in the "nsec entry" phase?
				// The previous code reused cursor=0 for menu. This is confusing.

				// Using cursor=50 for Nsec Entry, 100 for Password/Save choice.
				if m.cursor == 50 || m.cursor == 51 || m.cursor == 100 || m.cursor == 200 {
					m.textInput, cmd = m.textInput.Update(msg)
				}
			}
		} else {
			m.textInput, cmd = m.textInput.Update(msg)
		}
	}

	// Batch the spinner tick with whatever other cmd the input produced
	// so the spinner keeps animating across all Update paths.
	if spinnerCmd != nil {
		cmd = tea.Batch(cmd, spinnerCmd)
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
	case ScreenReplies:
		return m.handleRepliesEnter()
	}
	return m, nil
}

func (m Model) handleLoginEnter() (tea.Model, tea.Cmd) {
	hasProfiles := len(m.profiles) > 0

	if hasProfiles && !m.addingProfile {
		// Profile selection mode
		switch m.cursor {
		case 200: // Password entry for selected profile
			password := m.textInput.Value()
			if password == "" {
				m.message = "Please enter your password"
				m.messageStyle = errorStyle
				return m, nil
			}

			profile := m.profiles[m.selectedProfile]
			if m.onSelectProfile != nil {
				privKey, pubKey, err := m.onSelectProfile(profile.ID, password)
				if err != nil {
					m.message = fmt.Sprintf("Login failed: %v", err)
					m.messageStyle = errorStyle
					return m, nil
				}
				m.privateKey = privKey
				m.publicKey = pubKey
				m.currentProfileID = profile.ID
				m.currentProfileName = profile.Name
				m.loggedIn = true
				m.screen = ScreenHome
				m.message = ""
				m.textInput.Reset()
			}

		default: // Profile list selection
			addIdx := len(m.profiles)
			qrIdx := len(m.profiles) + 1

			if m.cursor < len(m.profiles) {
				// Selected a profile - go to password entry
				m.selectedProfile = m.cursor
				m.cursor = 200
				m.textInput.Placeholder = "Password..."
				m.textInput.EchoMode = textinput.EchoPassword
				m.textInput.Reset()
				m.textInput.Focus()
			} else if m.cursor == addIdx {
				// Add new profile
				m.addingProfile = true
				m.cursor = 50 // Start with name entry
				m.textInput.Placeholder = "Profile name..."
				m.textInput.EchoMode = textinput.EchoNormal
				m.textInput.Reset()
				m.textInput.Focus()
			} else if m.cursor == qrIdx {
				// QR Code Login
				m.screen = ScreenQRLogin
				m.qrReady = false
				m.message = "Generating QR code..."
				return m, m.initQR
			}
		}
	} else {
		// No profiles or adding new profile
		switch m.cursor {
		case 0:
			// "Create new profile" selected - start name entry
			m.addingProfile = true
			m.cursor = 50
			m.textInput.Placeholder = "Profile name..."
			m.textInput.EchoMode = textinput.EchoNormal
			m.textInput.Reset()
			m.textInput.Focus()

		case 50: // Profile name entered
			name := m.textInput.Value()
			if name == "" {
				name = "Default"
			}
			m.tempName = name
			m.cursor = 51
			m.textInput.Placeholder = "nsec1..."
			m.textInput.EchoMode = textinput.EchoNormal
			m.textInput.Reset()
			m.textInput.Focus()

		case 51: // Nsec entered
			nsec := m.textInput.Value()
			if nsec == "" || !strings.HasPrefix(nsec, "nsec") {
				m.message = "Please enter a valid nsec"
				m.messageStyle = errorStyle
				return m, nil
			}
			m.tempNsec = nsec
			m.cursor = 100
			m.textInput.Placeholder = "Password..."
			m.textInput.EchoMode = textinput.EchoPassword
			m.textInput.Reset()
			m.textInput.Focus()
			m.message = ""

		case 100: // Password entered - create profile
			password := m.textInput.Value()

			if m.onAddProfile != nil {
				pubKey, err := m.onAddProfile(m.tempName, m.tempNsec, password)
				if err != nil {
					m.message = fmt.Sprintf("Failed to add profile: %v", err)
					m.messageStyle = errorStyle
					m.cursor = 0
					m.addingProfile = false
					return m, nil
				}
				m.publicKey = pubKey
				m.currentProfileName = m.tempName

				// Reload profiles
				if m.onListProfiles != nil {
					profiles, lastUsed, _ := m.onListProfiles()
					m.profiles = profiles
					m.lastUsedProfileID = lastUsed
				}
			}

			m.loggedIn = true
			m.screen = ScreenHome
			m.message = "Profile created and logged in!"
			m.messageStyle = successStyle
			m.addingProfile = false
			m.tempName = ""
			m.tempNsec = ""

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
		Level:     qrterminal.L, // Lower error correction for smaller QR
		Writer:    &sb,
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
	case 2: // DMs
		m.screen = ScreenDMs
		m.dmLoading = true
		m.dmPosts = nil
		m.dmScroll = 0
		if m.onLoadDMs != nil && m.privateKey != "" {
			posts, err := m.onLoadDMs(m.privateKey)
			if err != nil {
				m.message = fmt.Sprintf("Failed to load DMs: %v", err)
				m.messageStyle = errorStyle
			} else {
				m.dmPosts = posts
			}
			m.dmLoading = false
		} else {
			m.message = "No private key available for decrypting DMs"
			m.messageStyle = errorStyle
			m.dmLoading = false
		}
	case 3: // Replies/Reactions
		m.screen = ScreenReplies
		m.replyLoading = true
		m.replyPosts = nil
		m.replyScroll = 0
		m.textInput.Placeholder = "Enter event ID to view replies..."
		m.textInput.Reset()
		m.textInput.Focus()
	case 4: // Tip
		m.screen = ScreenTip
		m.textInput.Placeholder = "Enter npub or lightning address..."
		m.textInput.Reset()
		m.textInput.Focus()
	case 5: // Relays
		m.screen = ScreenRelays
		m.addingRelay = false
		m.selectedRelay = 0
		if m.onLoadRelays != nil {
			relays, err := m.onLoadRelays()
			if err == nil {
				m.relays = relays
			}
		}
	case 6: // Switch Profile
		// Go back to login screen to select a different profile
		m.screen = ScreenLogin
		m.loggedIn = false
		m.cursor = 0
		m.textInput.Reset()
		// Reload profiles list
		if m.onListProfiles != nil {
			profiles, lastUsed, _ := m.onListProfiles()
			m.profiles = profiles
			m.lastUsedProfileID = lastUsed
		}
	case 7: // Quit
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

func (m Model) handleRepliesEnter() (tea.Model, tea.Cmd) {
	eventID := m.textInput.Value()
	if eventID == "" {
		m.message = "Please enter an event ID"
		m.messageStyle = errorStyle
		return m, nil
	}

	if m.onLoadReplies != nil {
		replies, err := m.onLoadReplies(eventID)
		if err != nil {
			m.message = fmt.Sprintf("Failed to load replies: %v", err)
			m.messageStyle = errorStyle
		} else {
			m.replyPosts = replies
			m.replyLoading = false
			m.replyScroll = 0
		}
	}

	m.textInput.Reset()
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
	case ScreenDMs:
		b.WriteString(m.viewDMs())
	case ScreenReplies:
		b.WriteString(m.viewReplies())
	case ScreenTip:
		b.WriteString(m.viewTip())
	case ScreenRelays:
		b.WriteString(m.viewRelays())
	}

	if m.message != "" {
		b.WriteString("\n" + m.messageStyle.Render(m.message))
	}

	// The QR screen ends with a block (title / QR / footer) that
	// viewQRLogin right-pads to a uniform width so everything in
	// the block shares an indent. The trailing global footer we
	// append here is OUTSIDE that block, so lipgloss.Place would
	// center it on its own and break the alignment. To keep the
	// whole screen visually coherent, append a short "press esc"
	// footer that wraps to the same block width as the rest.
	if m.screen == ScreenQRLogin {
		// Already inside viewQRLogin — nothing to append.
	} else {
		b.WriteString("\n\n" + menuStyle.Render("Press Esc to go back, Ctrl+C to quit"))
	}

	content := b.String()

	// Center content if we have terminal dimensions
	if m.width > 0 && m.height > 0 {
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, content)
	}

	return content
}

func (m Model) viewLogin() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("🦉 Welcome to Hoot!"))
	b.WriteString("\n\n")

	hasProfiles := len(m.profiles) > 0

	if hasProfiles && !m.addingProfile {
		// Profile selection mode
		switch m.cursor {
		case 200: // Password entry for selected profile
			profile := m.profiles[m.selectedProfile]
			displayName := profile.Name
			if displayName == "" {
				displayName = "Default"
			}
			b.WriteString(menuStyle.Render(fmt.Sprintf("Unlock profile: %s", displayName)))
			b.WriteString("\n\n")
			b.WriteString(m.textInput.View())
			b.WriteString("\n\n")
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("Press Esc to go back"))
		default: // Profile list
			b.WriteString(menuStyle.Render("Select a profile:"))
			b.WriteString("\n\n")

			for i, profile := range m.profiles {
				displayName := profile.Name
				if displayName == "" {
					displayName = "Default"
				}
				pubkeyShort := ""
				if len(profile.PublicKey) > 8 {
					pubkeyShort = profile.PublicKey[:8] + "..."
				}

				lastUsedMarker := ""
				if profile.ID == m.lastUsedProfileID {
					lastUsedMarker = " ★"
				}

				label := fmt.Sprintf("%s (%s)%s", displayName, pubkeyShort, lastUsedMarker)
				if i == m.cursor {
					b.WriteString(selectedStyle.Render(fmt.Sprintf("→ %s", label)))
				} else {
					b.WriteString(menuStyle.Render(fmt.Sprintf("  %s", label)))
				}
				b.WriteString("\n")
			}

			// Add new profile option
			addIdx := len(m.profiles)
			if m.cursor == addIdx {
				b.WriteString(selectedStyle.Render("→ + Add new profile"))
			} else {
				b.WriteString(menuStyle.Render("  + Add new profile"))
			}
			b.WriteString("\n")

			// QR Login option
			qrIdx := len(m.profiles) + 1
			if m.cursor == qrIdx {
				b.WriteString(selectedStyle.Render("→ 📱 Scan QR with Amber"))
			} else {
				b.WriteString(menuStyle.Render("  📱 Scan QR with Amber"))
			}
			b.WriteString("\n")
		}
	} else {
		// No profiles or adding new profile
		switch m.cursor {
		case 50: // Profile name entry
			b.WriteString(menuStyle.Render("Enter a name for this profile:"))
			b.WriteString("\n\n")
			b.WriteString(m.textInput.View())
		case 51: // Nsec entry
			b.WriteString(menuStyle.Render("Enter your Nostr private key (nsec):"))
			b.WriteString("\n\n")
			b.WriteString(m.textInput.View())
		case 100: // Password entry
			b.WriteString(menuStyle.Render("Create a password to protect this profile:"))
			b.WriteString("\n")
			b.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("(Leave empty to skip saving)"))
			b.WriteString("\n\n")
			b.WriteString(m.textInput.View())
		default:
			if m.addingProfile {
				b.WriteString(menuStyle.Render("Adding new profile..."))
				b.WriteString("\n\n")
				b.WriteString(menuStyle.Render("Press Enter to continue or Esc to cancel"))
			} else {
				b.WriteString(menuStyle.Render("No profiles yet. Let's create one!"))
				b.WriteString("\n\n")

				options := []string{
					"Create new profile",
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
	}

	return b.String()
}

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

func (m Model) viewHome() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("🦉 Hoot"))
	// Show current profile name if set
	if m.currentProfileName != "" {
		b.WriteString(menuStyle.Render(fmt.Sprintf(" - %s", m.currentProfileName)))
	} else if m.publicKey != "" && len(m.publicKey) >= 16 {
		b.WriteString(menuStyle.Render(fmt.Sprintf(" - %s...", m.publicKey[:16])))
	}
	b.WriteString("\n\n")

	menuItems := []string{
		"[p] Post a message",
		"[f] View feed",
		"[d] View DMs",
		"[e] View replies/reactions",
		"[t] Tip someone",
		"[r] Manage Relays",
		"[s] Switch Profile",
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

func (m Model) viewDMs() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("🔒 Your Direct Messages"))
	b.WriteString("\n\n")

	if m.dmLoading {
		b.WriteString(menuStyle.Render("Loading..."))
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
		b.WriteString(menuStyle.Render("Loading..."))
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
	HasKey        func() bool
	OnLoadKey     func(password string) (privateKey string, pubkey string, err error)
	OnResetKey    func() error
	OnLogin       func(nsec string, password string, save bool) (string, error)
	OnPost        func(message string) error
	OnLoadFeed    func() ([]FeedPost, error)
	OnLoadDMs     func(privateKey string) ([]FeedPost, error)
	OnLoadReplies func(eventID string) ([]FeedPost, error)
	OnInitQR      func() (string, error)
	OnCheckQR     func() (string, *nip46.ProfileMetadata, error)
	OnLoadRelays  func() ([]string, error)
	OnSaveRelays  func(relays []string) error
	// Profile callbacks
	OnListProfiles  func() ([]ProfileInfo, string, error)
	OnSelectProfile func(id, password string) (privKey, pubKey string, err error)
	OnAddProfile    func(name, nsec, password string) (pubKey string, err error)
	OnDeleteProfile func(id string) error
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
	m.onLoadDMs = cfg.OnLoadDMs
	m.onLoadReplies = cfg.OnLoadReplies
	m.onInitQR = cfg.OnInitQR
	m.onCheckQR = cfg.OnCheckQR
	m.onLoadRelays = cfg.OnLoadRelays
	m.onSaveRelays = cfg.OnSaveRelays
	m.onListProfiles = cfg.OnListProfiles
	m.onSelectProfile = cfg.OnSelectProfile
	m.onAddProfile = cfg.OnAddProfile
	m.onDeleteProfile = cfg.OnDeleteProfile

	// Load profiles on startup
	if m.onListProfiles != nil {
		profiles, lastUsed, err := m.onListProfiles()
		if err == nil {
			m.profiles = profiles
			m.lastUsedProfileID = lastUsed
			// Find and select last used profile
			for i, p := range profiles {
				if p.ID == lastUsed {
					m.selectedProfile = i
					break
				}
			}
		}
	}

	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
