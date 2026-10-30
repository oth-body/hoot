package tui

// typing reports whether a text field currently has focus, i.e. key
// presses should be treated as text rather than shortcuts.
func (m Model) typing() bool {
	switch m.screen {
	case ScreenLogin:
		return m.step.typing()
	case ScreenPost, ScreenReplies:
		return true
	case ScreenTip:
		return !m.tipping
	case ScreenRelays:
		return m.addingRelay
	}
	return false
}

// formControlKey reports keys that keep their command meaning even while a
// text field has focus.
func formControlKey(screen Screen, key string) bool {
	switch key {
	case "ctrl+c", "esc", "enter":
		return true
	case "up", "down":
		// The replies screen has an input *and* a scrollable result list.
		return screen == ScreenReplies
	}
	return false
}
