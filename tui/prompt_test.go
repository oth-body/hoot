package tui

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

const testNsec = "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"

// The nsec is masked while you type or paste it, and Ctrl+R toggles it.
func TestNsecIsMaskedWithRevealToggle(t *testing.T) {
	m := newModelFromConfig(Config{})
	m.startInput(stepNsec, "nsec1...", true)
	m = typeText(t, m, testNsec)
	if strings.Contains(m.View(), testNsec[:20]) {
		t.Fatalf("nsec visible while typing:\n%s", m.View())
	}
	if !strings.Contains(m.View(), "Ctrl+R to show") {
		t.Fatalf("no reveal hint:\n%s", m.View())
	}

	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyCtrlR})
	if !strings.Contains(m.View(), testNsec[len(testNsec)-20:]) || !strings.Contains(m.View(), "Ctrl+R to hide") {
		t.Fatalf("Ctrl+R didn't reveal:\n%s", m.View())
	}
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyCtrlR})
	if strings.Contains(m.View(), testNsec[len(testNsec)-20:]) {
		t.Fatalf("second Ctrl+R didn't hide:\n%s", m.View())
	}
	if m.textInput.Value() != testNsec {
		t.Fatalf("value changed: %q", m.textInput.Value())
	}
}

// Ctrl+R does nothing on ordinary prompts (and doesn't type an "r").
func TestRevealOnlyAppliesToSecretPrompts(t *testing.T) {
	m := newModelFromConfig(Config{})
	m.loggedIn, m.screen = true, ScreenPost
	m.openPrompt("What's on your mind?")
	m = typeText(t, m, "hello")
	before := m.textInput.EchoMode
	m, _ = press(t, m, tea.KeyMsg{Type: tea.KeyCtrlR})
	if m.textInput.EchoMode != before || m.textInput.Value() != "hello" {
		t.Fatalf("echo=%v value=%q", m.textInput.EchoMode, m.textInput.Value())
	}
}

// The unlock screen used to print "Press Esc to go back" twice (its own
// line plus the global footer).
func TestUnlockScreenShowsEscHintOnce(t *testing.T) {
	m := newModelFromConfig(Config{})
	m.startInput(stepUnlock, "Password...", true)
	if n := strings.Count(m.View(), "Press Esc to go back"); n != 1 {
		t.Fatalf("Esc hint shown %d times:\n%s", n, m.View())
	}
}

// Every prompt must open through openPrompt/openSecretPrompt (prompt.go),
// which reset the echo mode. Setting the placeholder or echo mode anywhere
// else is how the masked-reply bug happened.
func TestPromptsOnlyOpenThroughHelper(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	placeholder := regexp.MustCompile(`textInput\.Placeholder\s*=`)
	password := regexp.MustCompile(`EchoMode\s*=\s*textinput\.EchoPassword`)
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") || f == "prompt.go" {
			continue
		}
		src, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if placeholder.MatchString(line) || password.MatchString(line) {
				t.Errorf("%s:%d sets up the text field directly; use openPrompt/openSecretPrompt:\n\t%s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}
