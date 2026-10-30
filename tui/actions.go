package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

// Actions on the selected post in the feed or a thread: r reply, + (or l)
// like, z zap.

// reactedMsg delivers the result of a like.
type reactedMsg struct {
	name string
	err  error
}

// selectedPost is the post the action keys apply to: the highlighted feed
// post, or in a thread the highlighted reply (the thread's post itself if it
// has no replies yet).
func (m Model) selectedPost() (FeedPost, bool) {
	switch m.screen {
	case ScreenFeed:
		if m.feedScroll < len(m.feedPosts) {
			return m.feedPosts[m.feedScroll], true
		}
	case ScreenReplies:
		if m.threadPost == nil {
			return FeedPost{}, false
		}
		if m.replyScroll < len(m.replyPosts) {
			return m.replyPosts[m.replyScroll], true
		}
		return *m.threadPost, true
	}
	return FeedPost{}, false
}

// handleActionKey handles r / + / l / z on a post list. It reports whether
// the key was an action key.
func (m Model) handleActionKey(key string) (Model, tea.Cmd, bool) {
	if key != "r" && key != "+" && key != "l" && key != "z" {
		return m, nil, false
	}
	p, ok := m.selectedPost()
	if !ok || p.ID == "" {
		return m, nil, true
	}
	if p.Kind == 7 {
		m.message = "That's a reaction, not a post"
		m.messageStyle = errorStyle
		return m, nil, true
	}

	switch key {
	case "r":
		if m.onReply == nil {
			return m, nil, true
		}
		post := p
		m.replyTo = &post
		m.replyReturn = m.screen
		m.screen = ScreenPost
		m.message = ""
		m.textInput.Placeholder = "Write a reply..."
		m.textInput.Reset()
		m.textInput.Focus()
		return m, nil, true

	case "+", "l":
		if m.onReact == nil || m.reacting {
			return m, nil, true
		}
		m.reacting = true
		m.message = ""
		react, id, name := m.onReact, p.ID, authorLabel(p)
		return m, func() tea.Msg { return reactedMsg{name: name, err: react(id)} }, true

	case "z":
		if m.onZap == nil {
			return m, nil, true
		}
		post := p
		m.zapPost = &post
		m.tipReturn = m.screen
		m.screen = ScreenTip
		m.message = ""
		m.tipStep = 1
		m.tipTarget = authorLabel(p)
		m.textInput.Placeholder = "Amount in sats, e.g. 21"
		m.textInput.Reset()
		m.textInput.Focus()
		return m, nil, true
	}
	return m, nil, true
}

func (m Model) handleReacted(msg reactedMsg) (Model, tea.Cmd) {
	m.reacting = false
	if msg.err != nil {
		m.message = fmt.Sprintf("Like failed: %v", msg.err)
		m.messageStyle = errorStyle
	} else {
		m.message = fmt.Sprintf("❤ Liked %s's post", msg.name)
		m.messageStyle = successStyle
	}
	return m, nil
}

// leaveCompose returns from a reply composer or zap amount prompt to the
// list it was opened from.
func (m *Model) leaveCompose() {
	switch {
	case m.replyTo != nil:
		m.screen = m.replyReturn
		m.replyTo = nil
	case m.zapPost != nil:
		m.screen = m.tipReturn
		m.zapPost = nil
		m.resetTipForm()
	}
	m.textInput.Reset()
}
