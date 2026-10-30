package tui

import (
	"fmt"
	"hoot/nip46"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// loginStep is where the user is on the login screen. It used to be encoded
// in Model.cursor with magic values (50 = name, 51 = nsec, 100 = new
// password, 200 = unlock password) on top of its job as the menu index,
// which made every key handler guess which meaning applied.
type loginStep int

const (
	stepMenu          loginStep = iota // choosing from the login menu (cursor = row)
	stepProfileName                    // adding a profile: entering its name
	stepNsec                           // adding a profile: entering the nsec
	stepNewPassword                    // adding a profile: choosing a password
	stepUnlock                         // unlocking the selected profile
	stepConfirmDelete                  // confirming deletion of the selected profile
	stepConfirmForget                  // confirming forgetting the saved Amber session
)

// typingStep reports whether the step has a focused text field.
func (s loginStep) typing() bool {
	return s == stepProfileName || s == stepNsec || s == stepNewPassword || s == stepUnlock
}

type loginAction int

const (
	actProfile loginAction = iota
	actAddProfile
	actScanQR
	actRelays
	actResumeAmber
)

type loginItem struct {
	label   string
	action  loginAction
	profile int // index into m.profiles for actProfile
}

// loginMenuItems builds the login menu: saved profiles first, then actions.
func (m Model) loginMenuItems() []loginItem {
	var items []loginItem
	if m.savedAmberLabel != "" {
		items = append(items, loginItem{label: "📱 Continue as " + m.savedAmberLabel + " (Amber)", action: actResumeAmber})
	}
	if len(m.profiles) == 0 {
		return append(items,
			loginItem{label: "Create new profile", action: actAddProfile},
			loginItem{label: "Scan QR with Amber (NIP-46)", action: actScanQR},
			loginItem{label: "🔗 Configure relays", action: actRelays},
		)
	}
	for i, p := range m.profiles {
		name := p.Name
		if name == "" {
			name = "Default"
		}
		short := ""
		if len(p.PublicKey) > 8 {
			short = p.PublicKey[:8] + "..."
		}
		star := ""
		if p.ID == m.lastUsedProfileID {
			star = " ★"
		}
		items = append(items, loginItem{label: fmt.Sprintf("%s (%s)%s", name, short, star), action: actProfile, profile: i})
	}
	return append(items,
		loginItem{label: "+ Add new profile", action: actAddProfile},
		loginItem{label: "📱 Scan QR with Amber", action: actScanQR},
		loginItem{label: "🔗 Configure relays", action: actRelays},
	)
}

// startInput moves to a text-entry step with a fresh, focused field.
func (m *Model) startInput(step loginStep, placeholder string, secret bool) {
	m.step = step
	m.textInput.Placeholder = placeholder
	m.textInput.EchoMode = textinput.EchoNormal
	if secret {
		m.textInput.EchoMode = textinput.EchoPassword
	}
	m.textInput.Reset()
	m.textInput.Focus()
}

// backToLoginMenu abandons any in-progress login step.
func (m *Model) backToLoginMenu() {
	m.step = stepMenu
	m.tempName, m.tempNsec = "", ""
	m.textInput.Reset()
	m.textInput.EchoMode = textinput.EchoNormal
	m.message = ""
}

func (m *Model) reloadProfiles() {
	if m.onListProfiles == nil {
		return
	}
	profiles, lastUsed, err := m.onListProfiles()
	if err != nil {
		return
	}
	m.profiles = profiles
	m.lastUsedProfileID = lastUsed
	if n := len(m.loginMenuItems()); m.cursor >= n {
		m.cursor = n - 1
	}
}

// selectLastUsedProfile puts the menu cursor on the ★ profile.
func (m *Model) selectLastUsedProfile() {
	for i, it := range m.loginMenuItems() {
		if it.action == actProfile && m.profiles[it.profile].ID == m.lastUsedProfileID {
			m.cursor = i
			m.selectedProfile = it.profile
			return
		}
	}
}

func (m Model) handleLoginEnter() (tea.Model, tea.Cmd) {
	switch m.step {
	case stepMenu:
		items := m.loginMenuItems()
		if m.cursor < 0 || m.cursor >= len(items) {
			return m, nil
		}
		switch it := items[m.cursor]; it.action {
		case actProfile:
			m.selectedProfile = it.profile
			m.startInput(stepUnlock, "Password...", true)
		case actAddProfile:
			m.startInput(stepProfileName, "Profile name...", false)
		case actScanQR:
			m.screen = ScreenQRLogin
			m.qrReady = false
			m.message = "Generating QR code..."
			return m, m.initQR
		case actRelays:
			m.openRelaysFromLogin()
		case actResumeAmber:
			if m.resuming {
				return m, nil
			}
			m.resuming = true
			m.message = ""
			resume := m.onResumeAmber
			return m, func() tea.Msg {
				pk, profile, err := resume()
				return amberResumedMsg{pubkey: pk, profile: profile, err: err}
			}
		}

	case stepUnlock:
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
			m.currentProfileAbout = ""
			m.currentProfileNIP05 = ""
			m.loggedIn = true
			m.screen = ScreenHome
			m.step = stepMenu
			m.cursor = 0
			m.message = ""
			m.textInput.Reset()
		}

	case stepProfileName:
		name := strings.TrimSpace(m.textInput.Value())
		if name == "" {
			name = "Default"
		}
		m.tempName = name
		m.startInput(stepNsec, "nsec1...", false)

	case stepNsec:
		nsec := strings.TrimSpace(m.textInput.Value())
		if !strings.HasPrefix(nsec, "nsec") {
			m.message = "Please enter a valid nsec"
			m.messageStyle = errorStyle
			return m, nil
		}
		m.tempNsec = nsec
		m.message = ""
		m.startInput(stepNewPassword, "Password...", true)

	case stepNewPassword:
		password := m.textInput.Value()
		// The prompt used to say "Leave empty to skip saving", but an
		// empty password still saved the profile, just encrypted with ""
		// (i.e. effectively unprotected). Require one instead.
		if password == "" {
			m.message = "Please choose a password to encrypt your key"
			m.messageStyle = errorStyle
			return m, nil
		}
		if m.onAddProfile != nil {
			privKey, pubKey, err := m.onAddProfile(m.tempName, m.tempNsec, password)
			if err != nil {
				m.backToLoginMenu()
				m.message = fmt.Sprintf("Failed to add profile: %v", err)
				m.messageStyle = errorStyle
				return m, nil
			}
			m.privateKey = privKey
			m.publicKey = pubKey
			m.currentProfileName = m.tempName
			m.currentProfileAbout = ""
			m.currentProfileNIP05 = ""
			m.reloadProfiles()
		}
		m.loggedIn = true
		m.screen = ScreenHome
		m.step = stepMenu
		m.cursor = 0
		m.tempName, m.tempNsec = "", ""
		m.textInput.Reset()
		m.message = "Profile created and logged in!"
		m.messageStyle = successStyle
	}
	return m, nil
}

// handleLoginKey handles the login screen's letter keys outside text entry:
// x starts deleting the highlighted profile; y/n answer the confirmation.
// It reports whether it consumed the key.
func (m Model) handleLoginKey(key string) (Model, bool) {
	switch m.step {
	case stepMenu:
		if key != "x" {
			return m, false
		}
		items := m.loginMenuItems()
		if m.cursor < len(items) {
			switch it := items[m.cursor]; {
			case it.action == actProfile && m.onDeleteProfile != nil:
				m.selectedProfile = it.profile
				m.step = stepConfirmDelete
				m.message = ""
			case it.action == actResumeAmber && m.onForgetAmber != nil:
				m.step = stepConfirmForget
				m.message = ""
			}
		}
		return m, true

	case stepConfirmForget:
		switch key {
		case "y":
			if err := m.onForgetAmber(); err != nil {
				m.message = fmt.Sprintf("Couldn't forget the session: %v", err)
				m.messageStyle = errorStyle
			} else {
				m.message = "Forgot the saved Amber session"
				m.messageStyle = successStyle
			}
			m.step = stepMenu
			m.refreshSavedAmber()
			if n := len(m.loginMenuItems()); m.cursor >= n {
				m.cursor = n - 1
			}
		case "n":
			m.step = stepMenu
			m.message = ""
		default:
			return m, false
		}
		return m, true

	case stepConfirmDelete:
		switch key {
		case "y":
			p := m.profiles[m.selectedProfile]
			if err := m.onDeleteProfile(p.ID); err != nil {
				m.message = fmt.Sprintf("Delete failed: %v", err)
				m.messageStyle = errorStyle
			} else {
				m.message = fmt.Sprintf("Deleted profile %q", p.Name)
				m.messageStyle = successStyle
			}
			m.step = stepMenu
			m.reloadProfiles()
		case "n":
			m.step = stepMenu
			m.message = ""
		default:
			return m, false // esc / ctrl+c handled by the main key switch
		}
		return m, true
	}
	return m, false
}

// openRelaysFromLogin switches to the relay settings screen from the login
// menu, before any session exists.
func (m *Model) openRelaysFromLogin() {
	m.screen = ScreenRelays
	m.addingRelay = false
	m.selectedRelay = 0
	m.message = ""
	if m.onLoadRelays != nil {
		relays, err := m.onLoadRelays()
		if err == nil {
			m.relays = relays
		}
	}
}

func (m Model) viewLogin() string {
	var b strings.Builder
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))

	b.WriteString(titleStyle.Render("🦉 Welcome to Hoot!"))
	b.WriteString("\n\n")

	profileName := func() string {
		if m.selectedProfile < 0 || m.selectedProfile >= len(m.profiles) {
			return ""
		}
		if n := m.profiles[m.selectedProfile].Name; n != "" {
			return n
		}
		return "Default"
	}

	switch m.step {
	case stepUnlock:
		b.WriteString(menuStyle.Render(fmt.Sprintf("Unlock profile: %s", profileName())))
		b.WriteString("\n\n")
		b.WriteString(m.textInput.View())
		b.WriteString("\n\n")
		b.WriteString(dim.Render("Press Esc to go back"))

	case stepProfileName:
		b.WriteString(menuStyle.Render("Enter a name for this profile:"))
		b.WriteString("\n\n")
		b.WriteString(m.textInput.View())

	case stepNsec:
		b.WriteString(menuStyle.Render("Enter your Nostr private key (nsec):"))
		b.WriteString("\n\n")
		b.WriteString(m.textInput.View())

	case stepNewPassword:
		b.WriteString(menuStyle.Render("Create a password to protect this profile:"))
		b.WriteString("\n")
		b.WriteString(dim.Render("(Encrypts your key on this computer. It can't be recovered.)"))
		b.WriteString("\n\n")
		b.WriteString(m.textInput.View())

	case stepConfirmForget:
		b.WriteString(errorStyle.Render("Forget the saved Amber session?"))
		b.WriteString("\n\n")
		b.WriteString(menuStyle.Render("You'll need to scan a QR code with Amber to sign in again."))
		b.WriteString("\n")
		b.WriteString(menuStyle.Render("(To fully revoke access, also remove Hoot in Amber's app list.)"))
		b.WriteString("\n\n")
		b.WriteString(menuStyle.Render("Press y to forget, n or Esc to cancel"))

	case stepConfirmDelete:
		b.WriteString(errorStyle.Render(fmt.Sprintf("Delete profile %q?", profileName())))
		b.WriteString("\n\n")
		b.WriteString(menuStyle.Render("Its encrypted key is removed from this computer. This can't be undone;"))
		b.WriteString("\n")
		b.WriteString(menuStyle.Render("you'll need the nsec to add it again."))
		b.WriteString("\n\n")
		b.WriteString(menuStyle.Render("Press y to delete, n or Esc to cancel"))

	default: // stepMenu
		if len(m.profiles) == 0 {
			b.WriteString(menuStyle.Render("No profiles yet. Let's create one!"))
		} else {
			b.WriteString(menuStyle.Render("Select a profile:"))
		}
		b.WriteString("\n\n")
		for i, it := range m.loginMenuItems() {
			if i == m.cursor {
				b.WriteString(selectedStyle.Render("→ " + it.label))
			} else {
				b.WriteString(menuStyle.Render("  " + it.label))
			}
			b.WriteString("\n")
		}
		if m.resuming {
			b.WriteString("\n")
			b.WriteString(menuStyle.Render(m.spinner.View() + " Reconnecting to Amber... approve on your phone if it asks"))
			b.WriteString("\n")
		}
		if (len(m.profiles) > 0 && m.onDeleteProfile != nil) || m.savedAmberLabel != "" {
			b.WriteString("\n")
			b.WriteString(dim.Render("x: delete the selected profile / forget the saved Amber session"))
		}
	}
	return b.String()
}

// amberResumedMsg delivers the result of reconnecting a saved Amber session.
type amberResumedMsg struct {
	pubkey  string
	profile *nip46.ProfileMetadata
	err     error
}

func (m *Model) refreshSavedAmber() {
	m.savedAmberLabel = ""
	if m.onSavedAmber != nil && m.onResumeAmber != nil {
		if label, ok := m.onSavedAmber(); ok {
			m.savedAmberLabel = label
		}
	}
}

// loginRemote finishes a sign-in through a remote signer (QR pairing or a
// resumed session): no local key, profile metadata from kind 0.
func (m *Model) loginRemote(pubkey string, profile *nip46.ProfileMetadata) {
	m.privateKey = ""
	m.currentProfileID = ""
	m.publicKey = pubkey
	m.loggedIn = true
	m.screen = ScreenHome
	m.step = stepMenu
	m.cursor = 0
	m.currentProfileName = ""
	m.currentProfileAbout = ""
	m.currentProfileNIP05 = ""
	// The signer-published name wins over the raw key: people recognise
	// themselves by name. With no kind-0 profile the home screen shows
	// the npub.
	if profile != nil && profile.Name != "" {
		m.currentProfileName = profile.Name
		m.message = fmt.Sprintf("Logged in as %s", profile.Name)
	} else {
		m.message = "Logged in via Amber!"
	}
	if profile != nil {
		m.currentProfileAbout = profile.About
		m.currentProfileNIP05 = profile.NIP05
	}
	m.messageStyle = successStyle
}
