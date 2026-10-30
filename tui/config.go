package tui

import (
	"hoot/nip46"

	tea "github.com/charmbracelet/bubbletea"
)

// Config holds all the callbacks for TUI operations
type Config struct {
	HasKey     func() bool
	OnLoadKey  func(password string) (privateKey string, pubkey string, err error)
	OnResetKey func() error
	OnLogin    func(nsec string, password string, save bool) (string, error)
	OnPost     func(message string) error
	OnLoadFeed func() ([]FeedPost, error)
	// OnLoadFollowingFeed loads posts from people the user follows (kind-3
	// contact list). Optional: without it the feed is global-only.
	OnLoadFollowingFeed func() ([]FeedPost, error)
	OnLoadDMs           func(privateKey string) ([]FeedPost, error)
	OnLoadReplies       func(eventID string) ([]FeedPost, error)
	OnInitQR            func() (string, error)
	OnCheckQR           func() (string, *nip46.ProfileMetadata, error)
	OnLoadRelays        func() ([]string, error)
	OnSaveRelays        func(relays []string) error
	// Profile callbacks
	OnListProfiles  func() ([]ProfileInfo, string, error)
	OnSelectProfile func(id, password string) (privKey, pubKey string, err error)
	OnAddProfile    func(name, nsec, password string) (privKey, pubKey string, err error)
	OnDeleteProfile func(id string) error
	// OnLogout clears the host's signing state (see Model.onLogout).
	OnLogout func()
	// OnReply publishes a reply to parentID.
	OnReply func(parentID, content string) error
	// OnReact likes eventID.
	OnReact func(eventID string) error
	// OnZap zaps a post's author (NIP-57, falling back to a plain tip) and
	// returns a one-line summary.
	OnZap func(pubkey, eventID string, sats int64) (string, error)
	// OnTip pays a tip (see Model.onTip).
	OnTip func(target string, sats int64) (string, error)
}

// newModelFromConfig builds a Model wired to cfg's callbacks. Split out of
// Run so tests can drive the exact model the real program uses.
func newModelFromConfig(cfg Config) Model {
	m := NewModel()
	m.hasKey = cfg.HasKey
	m.onLoadKey = cfg.OnLoadKey
	m.onResetKey = cfg.OnResetKey
	m.onLogin = cfg.OnLogin
	m.onPost = cfg.OnPost
	m.onLoadFeed = cfg.OnLoadFeed
	m.onLoadFollowingFeed = cfg.OnLoadFollowingFeed
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
	m.onLogout = cfg.OnLogout
	m.onReply = cfg.OnReply
	m.onReact = cfg.OnReact
	m.onZap = cfg.OnZap
	m.onTip = cfg.OnTip

	// Load profiles on startup
	if m.onListProfiles != nil {
		profiles, lastUsed, err := m.onListProfiles()
		if err == nil {
			m.profiles = profiles
			m.lastUsedProfileID = lastUsed
			m.selectLastUsedProfile()
		}
	}

	return m
}

// Run starts the TUI with the given configuration
func Run(cfg Config) error {
	m := newModelFromConfig(cfg)
	p := tea.NewProgram(m, tea.WithAltScreen())
	_, err := p.Run()
	return err
}
