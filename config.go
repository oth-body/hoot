package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	appName          = "hoot"
	keyFileName      = "nostr_key.enc"
	profilesFileName = "profiles.json"
)

// defaultRelays is the set of relays hoot publishes to when the user
// has no relays.txt configured. The list is de-duplicated at module
// load (see init()) — historically this slice contained wss://nostr.wine
// twice, which caused every post to be sent to the same relay in
// parallel (and double-counted in `success`).
var defaultRelays = []string{
	"wss://relay.damus.io",
	"wss://relay.nostr.band",
	"wss://nostr.wine",
}

func init() {
	// Dedupe defaultRelays. If you add a new default relay and accidentally
	// paste an existing one, this catches it at process start instead of
	// at every publish.
	seen := make(map[string]struct{}, len(defaultRelays))
	deduped := defaultRelays[:0]
	for _, r := range defaultRelays {
		if _, ok := seen[r]; ok {
			continue
		}
		seen[r] = struct{}{}
		deduped = append(deduped, r)
	}
	defaultRelays = deduped
}

func getConfigDir() string {
	var configDir string
	switch runtime.GOOS {
	case "windows":
		configDir = os.Getenv("APPDATA")
	case "darwin":
		configDir = filepath.Join(os.Getenv("HOME"), "Library", "Application Support")
	default: // Unix-like systems
		configDir = os.Getenv("XDG_CONFIG_HOME")
		if configDir == "" {
			configDir = filepath.Join(os.Getenv("HOME"), ".config")
		}
	}
	return filepath.Join(configDir, appName)
}

// loadRelays attempts to read relay URLs from a local "relays.txt" file first,
// if not found then it checks the config directory.
func loadRelays() ([]string, error) {
	// First, try the current directory.
	localRelayPath := "relays.txt"
	data, err := os.ReadFile(localRelayPath)
	if err != nil {
		// If not found, try the config directory.
		configDir := getConfigDir()
		relayPath := filepath.Join(configDir, "relays.txt")
		data, err = os.ReadFile(relayPath)
		if err != nil {
			return nil, err
		}
	}
	lines := strings.Split(string(data), "\n")
	var relays []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "//") { // ignore commented lines
			relays = append(relays, line)
		}
	}
	return relays, nil
}

// getRelayList returns relay URLs from the "relays.txt" file or falls back to default if needed.
func getRelayList() []string {
	relays, err := loadRelays()
	if (err != nil) || (len(relays) == 0) {
		return defaultRelays
	}
	return relays
}
