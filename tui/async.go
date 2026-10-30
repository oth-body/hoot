package tui

import (
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
)

// Network work (loading the feed, DMs or replies, publishing a post) runs in
// a tea.Cmd so the UI keeps drawing — previously these calls ran inside
// Update and froze the whole screen for up to 10-15s.

// loadedMsg delivers the result of a background load for one screen.
type loadedMsg struct {
	screen Screen
	gen    int // matches Model.loadGen when the result is still wanted
	posts  []FeedPost
	err    error
}

// postedMsg delivers the result of publishing a note.
type postedMsg struct{ err error }

// startLoad runs fn in the background and tags the result with a new
// generation number. Any result from an earlier request (e.g. the user left
// the screen and came back) is ignored when it arrives.
func (m *Model) startLoad(screen Screen, fn func() ([]FeedPost, error)) tea.Cmd {
	m.loadGen++
	gen := m.loadGen
	return func() tea.Msg {
		posts, err := fn()
		return loadedMsg{screen: screen, gen: gen, posts: posts, err: err}
	}
}

func (m Model) handleLoaded(msg loadedMsg) (Model, tea.Cmd) {
	if msg.gen != m.loadGen || msg.screen != m.screen {
		return m, nil // stale
	}
	what := map[Screen]string{ScreenFeed: "feed", ScreenDMs: "DMs", ScreenReplies: "replies"}[msg.screen]
	if msg.err != nil {
		m.message = fmt.Sprintf("Failed to load %s: %v", what, msg.err)
		m.messageStyle = errorStyle
	}
	switch msg.screen {
	case ScreenFeed:
		m.feedLoading = false
		m.feedPosts = msg.posts
		m.feedScroll = 0
	case ScreenDMs:
		m.dmLoading = false
		m.dmPosts = msg.posts
		m.dmScroll = 0
	case ScreenReplies:
		m.replyLoading = false
		m.replyPosts = msg.posts
		m.replyScroll = 0
	}
	return m, nil
}

func (m Model) handlePosted(msg postedMsg) (Model, tea.Cmd) {
	m.posting = false
	if msg.err != nil {
		// Stay in the composer with the text intact so it can be retried.
		m.message = fmt.Sprintf("Failed to post: %v", msg.err)
		m.messageStyle = errorStyle
		return m, nil
	}
	m.message = "Posted successfully!"
	m.messageStyle = successStyle
	m.textInput.Reset()
	if m.screen == ScreenPost {
		m.screen = ScreenHome
		m.cursor = 0
	}
	return m, nil
}
