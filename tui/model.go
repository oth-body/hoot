package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"hoot/nip46"
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
	ID         string // hex event ID ("" for synthetic entries)
	Kind       int
	Author     string // hex pubkey
	AuthorName string // display name from the author's profile, if known
	Content    string
	CreatedAt  string
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

	// Login screen state (see login.go)
	step     loginStep
	tempNsec string // nsec entered while adding a profile
	tempName string // profile name entered while adding a profile

	// Profile state
	profiles            []ProfileInfo
	selectedProfile     int    // index in profile list
	currentProfileID    string // ID of logged-in profile
	currentProfileName  string // display name (from kind-0 metadata if Amber login, otherwise user-set name)
	currentProfileAbout string // "about" line from kind-0 metadata (Amber login only)
	currentProfileNIP05 string // NIP-05 identifier from kind-0 metadata (Amber login only)
	lastUsedProfileID   string

	// Background work (see async.go)
	loadGen int  // bumped per load; stale results are dropped
	posting bool // a post is being published

	// Feed state (the *Scroll fields are the selected index)
	feedFollowing bool      // following feed instead of global
	threadPost    *FeedPost // post whose replies are shown (opened from a list)
	threadFrom    Screen    // screen to return to from the thread
	feedPosts     []FeedPost
	feedLoading   bool
	feedScroll    int

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
	onLogin    func(nsec string, password string, save bool) (string, error) // returns pubkey
	onPost     func(message string) error
	onLoadKey  func(password string) (privateKey string, pubkey string, err error)
	onResetKey func() error
	onLoadFeed func() ([]FeedPost, error)
	// onLoadFollowingFeed loads posts from people the user follows.
	onLoadFollowingFeed func() ([]FeedPost, error)
	onLoadDMs           func(privateKey string) ([]FeedPost, error)
	onLoadReplies       func(eventID string) ([]FeedPost, error)
	onInitQR            func() (string, error)
	onCheckQR           func() (string, *nip46.ProfileMetadata, error)
	onLoadRelays        func() ([]string, error)
	onSaveRelays        func(relays []string) error
	hasKey              func() bool

	// Profile callbacks
	onListProfiles  func() ([]ProfileInfo, string, error) // returns profiles + lastUsedID
	onSelectProfile func(id, password string) (privKey, pubKey string, err error)
	onAddProfile    func(name, nsec, password string) (privKey, pubKey string, err error)
	onDeleteProfile func(id string) error

	// onLogout tears down whatever signing session the host process holds
	// (a NIP-46 remote-signer session and/or a cached local private key).
	// Called on "Switch Profile" and when the user backs out of the QR
	// screen, so a stale session can never sign events for the next login.
	onLogout func()

	// Post actions (see actions.go)
	onReply func(parentID, content string) error
	onReact func(eventID string) error
	onZap   func(pubkey, eventID string, sats int64) (string, error)

	replyTo     *FeedPost // composer is replying to this post
	replyReturn Screen    // where to go after the reply
	zapPost     *FeedPost // tip screen is zapping this post
	tipReturn   Screen    // where to go after the zap
	reacting    bool

	// onTip pays sats to target (lightning address, npub or hex pubkey)
	// and returns a one-line summary. It blocks until the wallet answers,
	// so the model runs it in a tea.Cmd.
	onTip func(target string, sats int64) (string, error)

	// Tip screen state
	tipStep   int    // 0 = entering recipient, 1 = entering amount
	tipTarget string // recipient from step 0
	tipping   bool   // payment in flight
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
		key := msg.String()

		// While a text field has focus, every key except the few that
		// control the form goes to the field. Previously letters were
		// matched against shortcuts first: typing "k" or "j" moved the
		// menu cursor mid-form (breaking the add-profile flow), and "r"
		// in a password field deleted the stored key file.
		if m.typing() && !formControlKey(m.screen, key) {
			m.textInput, cmd = m.textInput.Update(msg)
			return m, tea.Batch(cmd, spinnerCmd)
		}

		// Home menu shortcuts: the menu shows "[p] Post a message" etc.,
		// but only q was actually bound.
		if m.screen == ScreenHome {
			if idx, ok := homeShortcuts[key]; ok {
				m.cursor = idx
				return m.handleHomeEnter()
			}
		}
		if m.screen == ScreenLogin {
			if nm, ok := m.handleLoginKey(key); ok {
				return nm, nil
			}
		}
		if m.screen == ScreenFeed || (m.screen == ScreenReplies && m.threadPost != nil) {
			if nm, cmd, ok := m.handleActionKey(key); ok {
				return nm, cmd
			}
		}
		if m.screen == ScreenFeed && key == "g" && m.onLoadFollowingFeed != nil {
			m.feedFollowing = !m.feedFollowing
			return m, m.reloadFeed()
		}

		switch key {
		case "ctrl+c":
			// The footer promises "Ctrl+C to quit" on every screen.
			// Previously ctrl+c shared the esc branch and only went back.
			return m, tea.Quit

		case "esc":
			if m.screen == ScreenRelays && m.addingRelay {
				// Cancel just the "new relay" sub-form, not the whole screen.
				m.addingRelay = false
				m.textInput.Reset()
				m.message = ""
				return m, nil
			}
			if m.screen == ScreenLogin {
				if m.step != stepMenu {
					// Inside a sub-form (name / nsec / password / delete
					// confirmation): back out to the menu, don't quit.
					m.backToLoginMenu()
					return m, nil
				}
				return m, tea.Quit
			}
			if m.screen == ScreenQRLogin {
				// Abandon the pairing attempt. Previously esc fell through
				// to "go Home", dropping an unauthenticated user onto the
				// home menu with a half-initialised NIP-46 session that
				// publishPostTUI would then try (and fail) to sign with.
				m.logout()
				m.screen = ScreenLogin
				m.cursor = 0
				m.message = ""
				return m, nil
			}
			if !m.loggedIn {
				// Relays (or any other screen) opened from the login menu:
				// there is no Home screen to return to.
				m.screen = ScreenLogin
				m.cursor = 0
				m.message = ""
				return m, nil
			}
			if (m.screen == ScreenPost && m.replyTo != nil) || (m.screen == ScreenTip && m.zapPost != nil && !m.tipping) {
				// Cancel a reply or zap: back to the list, not Home.
				m.leaveCompose()
				m.message = ""
				return m, nil
			}
			if m.screen == ScreenReplies && m.threadPost != nil {
				// Back from a thread to the list it was opened from.
				m.threadPost = nil
				m.replyPosts = nil
				m.screen = m.threadFrom
				m.message = ""
				return m, nil
			}
			// Go back to home from other screens
			m.screen = ScreenHome
			m.message = ""
			return m, nil

		case "q":
			if m.screen == ScreenHome {
				return m, tea.Quit
			}

		case "a":
			if m.screen == ScreenRelays && !m.addingRelay {
				m.addingRelay = true
				m.textInput.Placeholder = "wss://relay.example.com"
				m.textInput.EchoMode = textinput.EchoNormal
				m.textInput.Reset()
				m.textInput.Focus()
				m.message = ""
				return m, nil
			}

		case "d":
			if m.screen == ScreenRelays && !m.addingRelay && len(m.relays) > 0 {
				idx := m.selectedRelay
				removed := m.relays[idx]
				m.relays = append(m.relays[:idx], m.relays[idx+1:]...)
				if m.selectedRelay >= len(m.relays) && m.selectedRelay > 0 {
					m.selectedRelay--
				}
				if m.onSaveRelays != nil {
					if err := m.onSaveRelays(m.relays); err != nil {
						m.message = fmt.Sprintf("Failed to save relays: %v", err)
						m.messageStyle = errorStyle
						return m, nil
					}
				}
				m.message = fmt.Sprintf("Removed %s", removed)
				m.messageStyle = successStyle
				return m, nil
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
			case ScreenRelays:
				if !m.addingRelay && m.selectedRelay > 0 {
					m.selectedRelay--
				}
			case ScreenLogin:
				if m.step == stepMenu && m.cursor > 0 {
					m.cursor--
				}
			default:
				if m.cursor > 0 {
					m.cursor--
				}
			}

		case "down", "j":
			switch m.screen {
			case ScreenFeed:
				if m.feedScroll < len(m.feedPosts)-1 {
					m.feedScroll++
				}
			case ScreenDMs:
				if m.dmScroll < len(m.dmPosts)-1 {
					m.dmScroll++
				}
			case ScreenReplies:
				if m.replyScroll < len(m.replyPosts)-1 {
					m.replyScroll++
				}
			case ScreenRelays:
				if !m.addingRelay && m.selectedRelay < len(m.relays)-1 {
					m.selectedRelay++
				}
			case ScreenLogin:
				if m.step == stepMenu && m.cursor < len(m.loginMenuItems())-1 {
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
		if m.screen != ScreenQRLogin {
			// A check that was already in flight when the user pressed
			// esc. The session was torn down; don't log them in.
			return m, nil
		}
		m.privateKey = "" // remote signer: no local key
		m.currentProfileID = ""
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
		m.currentProfileName = ""
		m.currentProfileAbout = ""
		m.currentProfileNIP05 = ""
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

	case loadedMsg:
		return m.handleLoaded(msg)

	case postedMsg:
		return m.handlePosted(msg)

	case tipResultMsg:
		m.tipping = false
		what := "Tip"
		if m.zapPost != nil {
			what = "Zap"
			m.leaveCompose()
		}
		if msg.err != nil {
			m.message = fmt.Sprintf("%s failed: %v", what, msg.err)
			m.messageStyle = errorStyle
		} else {
			m.message = "⚡ " + msg.summary
			m.messageStyle = successStyle
		}
		m.resetTipForm()
		return m, nil

	case reactedMsg:
		return m.handleReacted(msg)

	case checkQRTickMsg:
		// Fired by the retry timer above — run another check, unless the
		// user has since left the QR screen (esc), in which case the
		// polling loop ends here.
		if m.screen != ScreenQRLogin {
			return m, nil
		}
		return m, m.checkQRConnection
	}

	// Non-key messages (cursor blink etc.) go to the text field when one
	// has focus. Keys were routed at the top of the KeyMsg case.
	if _, isKey := msg.(tea.KeyMsg); !isKey && m.typing() {
		var inputCmd tea.Cmd
		m.textInput, inputCmd = m.textInput.Update(msg)
		cmd = tea.Batch(cmd, inputCmd)
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
		if m.threadPost != nil {
			if m.replyScroll < len(m.replyPosts) {
				return m, m.openThread(m.replyPosts[m.replyScroll], m.threadFrom)
			}
			return m, nil
		}
		return m.handleRepliesEnter()
	case ScreenFeed:
		if m.feedScroll < len(m.feedPosts) {
			return m, m.openThread(m.feedPosts[m.feedScroll], ScreenFeed)
		}
		return m, nil
	case ScreenRelays:
		return m.handleRelaysEnter()
	case ScreenTip:
		return m.handleTipEnter()
	}
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

// logout clears all login state in the model and asks the host process to
// drop its signing session.
func (m *Model) logout() {
	if m.onLogout != nil {
		m.onLogout()
	}
	m.loggedIn = false
	m.privateKey = ""
	m.publicKey = ""
	m.currentProfileID = ""
	m.currentProfileName = ""
	m.currentProfileAbout = ""
	m.currentProfileNIP05 = ""
	m.qrData = ""
	m.qrRendered = ""
	m.qrReady = false
}
