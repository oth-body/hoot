package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"hoot/cache"
	"hoot/nip46"
	"hoot/tui"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip04"
	"github.com/nbd-wtf/go-nostr/nip19"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
	"sync"
)

const (
	appName          = "nostr-cli"
	keyFileName      = "nostr_key.enc"
	profilesFileName = "profiles.json"
	version          = "0.0.4" // Define the version here

	// Tip validation constants
	minTipSats int64 = 1      // Minimum 1 sat
	maxTipSats int64 = 100000 // Maximum 100k sats (~$50-100 USD)

	// Post/feed limits
	defaultPostLimit = 4  // Number of posts to fetch by default
	feedPostLimit    = 20 // Number of posts in feed

	// Spinner animation
	spinnerDelayMs = 100 // Milliseconds between spinner frames

	// Crypto parameters for key derivation
	scryptN     = 32768 // CPU/memory cost parameter
	scryptR     = 8     // Block size parameter
	scryptP     = 1     // Parallelization parameter
	keyLength   = 32    // Derived key length in bytes
	saltLength  = 32    // Salt length in bytes
	nonceLength = 24    // Nonce length in bytes

	// Timestamp validation constants
	// nostr timestamps are seconds since Unix epoch (Jan 1, 1970)
	// Min: reasonable past (year 2020)
	// Max: reasonable future (year 2100)
	timestampMin int64 = 1577836800  // 2020-01-01 00:00:00 UTC
	timestampMax int64 = 4102444800  // 2100-01-01 00:00:00 UTC

	// bcrypt cost range
	bcryptCostMin = 4
	bcryptCostMax = 31
)

// bcryptCost is the cost parameter for bcrypt password hashing.
// Default is 10 (bcrypt.DefaultCost). Can be configured via HOOT_BCRYPT_COST env var.
var bcryptCost = 10

func init() {
	if v := os.Getenv("HOOT_BCRYPT_COST"); v != "" {
		if cost, err := strconv.Atoi(v); err == nil && cost >= bcryptCostMin && cost <= bcryptCostMax {
			bcryptCost = cost
		} else {
			log.Printf("Invalid HOOT_BCRYPT_COST value %q: must be integer between %d and %d, using default %d",
				v, bcryptCostMin, bcryptCostMax, bcryptCost)
		}
	}
}

// ValidateTimestamp checks if a nostr timestamp is within reasonable bounds
// This prevents overflow issues and rejects obviously invalid timestamps
func ValidateTimestamp(ts int64) error {
	if ts < timestampMin {
		return fmt.Errorf("timestamp %d is before year 2020 (too old)", ts)
	}
	if ts > timestampMax {
		return fmt.Errorf("timestamp %d is after year 2100 (too far in future)", ts)
	}
	return nil
}

// TimeoutConfig holds configurable timeout values
type TimeoutConfig struct {
	RelayConnect time.Duration
	Query        time.Duration
	DMQuery      time.Duration
	SignEvent    time.Duration
	Publish      time.Duration
}

// DefaultTimeouts returns the default timeout configuration
func DefaultTimeouts() TimeoutConfig {
	return TimeoutConfig{
		RelayConnect: 10 * time.Second,
		Query:        10 * time.Second,
		DMQuery:       15 * time.Second,
		SignEvent:     30 * time.Second,
		Publish:       5 * time.Second,
	}
}

// LoadTimeoutsFromEnv loads timeout configuration from environment variables
func LoadTimeoutsFromEnv() TimeoutConfig {
	cfg := DefaultTimeouts()

	if v := os.Getenv("HOOT_RELAY_CONNECT_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.RelayConnect = d
		}
	}
	if v := os.Getenv("HOOT_QUERY_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Query = d
		}
	}
	if v := os.Getenv("HOOT_DM_QUERY_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.DMQuery = d
		}
	}
	if v := os.Getenv("HOOT_SIGN_EVENT_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.SignEvent = d
		}
	}
	if v := os.Getenv("HOOT_PUBLISH_TIMEOUT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Publish = d
		}
	}

	return cfg
}

// Global timeout configuration (loaded at startup)
var timeouts TimeoutConfig

func init() {
	timeouts = LoadTimeoutsFromEnv()
}

var defaultRelays = []string{
	"wss://relay.damus.io",
	"wss://relay.nostr.band",
	"wss://nostr.wine",
	"wss://relay.primal.net",
}

// Global NIP-46 session and local key
var (
	nip46Session   *nip46.Session
	localPrivateKey string
	eventCache     *cache.Cache

	// Mutex for thread-safe access to global variables
	globalMutex sync.RWMutex
)

// Thread-safe getters for global variables
func getNIP46Session() *nip46.Session {
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	return nip46Session
}

func setNIP46Session(s *nip46.Session) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	nip46Session = s
}

func getLocalPrivateKey() string {
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	return localPrivateKey
}

func setLocalPrivateKey(k string) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	localPrivateKey = k
}

func getEventCache() *cache.Cache {
	globalMutex.RLock()
	defer globalMutex.RUnlock()
	return eventCache
}

func setEventCache(c *cache.Cache) {
	globalMutex.Lock()
	defer globalMutex.Unlock()
	eventCache = c
}

// Updated StoredKey includes the password hash.
type StoredKey struct {
	EncryptedKey []byte `json:"encrypted_key"`
	Salt         []byte `json:"salt"`
	// PasswordHash stores the bcrypt hash of the password.
	PasswordHash string `json:"password_hash"`
}

// Profile represents a single saved Nostr account
type Profile struct {
	ID           string    `json:"id"`
	Name         string    `json:"name"`
	PublicKey    string    `json:"public_key"` // hex pubkey
	EncryptedKey []byte    `json:"encrypted_key"`
	Salt         []byte    `json:"salt"`
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
}

// ProfileStore holds all saved profiles and tracks last used
type ProfileStore struct {
	LastUsedProfile string              `json:"last_used_profile"`
	Profiles        map[string]*Profile `json:"profiles"`
}

// ProfileInfo is a lightweight struct for TUI display
type ProfileInfo struct {
	ID        string
	Name      string
	PublicKey string
}

func withLoading(message string, fn func() error) error {
	done := make(chan bool)
	go func() {
		spinner := []rune{'|', '/', '-', '\\'}
		i := 0
		for {
			select {
			case <-done:
				return
			default:
				fmt.Printf("\r%s %c", message, spinner[i%len(spinner)])
				i++
				time.Sleep(spinnerDelayMs * time.Millisecond)
			}
		}
	}()
	err := fn()
	done <- true
	// Clear the loading line
	fmt.Printf("\r%s done\n", message)
	return err
}

// hashPassword creates a bcrypt hash of the given password.
func hashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(hashedBytes), nil
}

// checkPassword verifies that the provided password matches the hashed one.
func checkPassword(hashedPassword, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
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

// isValidRelayURL checks if a URL is a valid websocket relay URL.
// Only ws:// and wss:// schemes are accepted, and host must not be empty.
func isValidRelayURL(urlStr string) bool {
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	return (u.Scheme == "wss" || u.Scheme == "ws") && u.Host != ""
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
			if !isValidRelayURL(line) {
				log.Printf("Warning: skipping invalid relay URL: %s", line)
				continue
			}
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

func deriveKey(password []byte, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, scryptN, scryptR, scryptP, keyLength)
}

func encryptKey(key []byte, password []byte) (*StoredKey, error) {
	// Generate salt
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// Derive encryption key from password and salt
	derivedKey, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	// Generate nonce
	var nonce [nonceLength]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}

	// Encrypt the key
	var secretKey [32]byte
	copy(secretKey[:], derivedKey[:32])
	encryptedKey := secretbox.Seal(nonce[:], key, &nonce, &secretKey)

	// Generate bcrypt hash of the password.
	pwdHash, err := hashPassword(string(password))
	if err != nil {
		return nil, err
	}

	return &StoredKey{
		EncryptedKey: encryptedKey,
		Salt:         salt,
		PasswordHash: pwdHash,
	}, nil
}

func decryptKey(storedKey *StoredKey, password []byte) ([]byte, error) {
	// Verify that the provided password matches the stored hash.
	if storedKey.PasswordHash != "" {
		if err := checkPassword(storedKey.PasswordHash, string(password)); err != nil {
			return nil, fmt.Errorf("password verification failed: %w", err)
		}
	}

	// Derive encryption key from password and salt
	derivedKey, err := deriveKey(password, storedKey.Salt)
	if err != nil {
		return nil, err
	}

	// Prepare nonce and secret key
	var nonce [nonceLength]byte
	copy(nonce[:], storedKey.EncryptedKey[:nonceLength])
	var secretKey [keyLength]byte
	copy(secretKey[:], derivedKey[:keyLength])

	// Decrypt the key
	decryptedKey, ok := secretbox.Open(nil, storedKey.EncryptedKey[nonceLength:], &nonce, &secretKey)
	if !ok {
		return nil, fmt.Errorf("decryption failed")
	}

	return decryptedKey, nil
}

func saveKey(key string, password []byte) error {
	// Ensure config directory exists
	configDir := getConfigDir()
	err := os.MkdirAll(configDir, 0700)
	if err != nil {
		return err
	}

	// Encrypt the key
	storedKey, err := encryptKey([]byte(key), password)
	if err != nil {
		return err
	}

	// Convert to JSON
	jsonData, err := json.Marshal(storedKey)
	if err != nil {
		return err
	}

	// Save to file
	keyPath := filepath.Join(configDir, keyFileName)
	return os.WriteFile(keyPath, jsonData, 0600)
}

func loadKey(password []byte) (string, error) {
	// Get key file path
	configDir := getConfigDir()
	keyPath := filepath.Join(configDir, keyFileName)

	// Read encrypted key
	jsonData, err := os.ReadFile(keyPath)
	if err != nil {
		return "", err
	}

	// Unmarshal stored key
	var storedKey StoredKey
	err = json.Unmarshal(jsonData, &storedKey)
	if err != nil {
		return "", err
	}

	// Decrypt the key
	decryptedKey, err := decryptKey(&storedKey, password)
	if err != nil {
		return "", err
	}

	return string(decryptedKey), nil
}

// LoadProfiles loads the profile store from disk
func LoadProfiles() (*ProfileStore, error) {
	configDir := getConfigDir()
	profilesPath := filepath.Join(configDir, profilesFileName)

	data, err := os.ReadFile(profilesPath)
	if err != nil {
		if os.IsNotExist(err) {
			// Return empty store
			return &ProfileStore{
				Profiles: make(map[string]*Profile),
			}, nil
		}
		return nil, err
	}

	var store ProfileStore
	if err := json.Unmarshal(data, &store); err != nil {
		return nil, err
	}

	if store.Profiles == nil {
		store.Profiles = make(map[string]*Profile)
	}

	return &store, nil
}

// SaveProfiles saves the profile store to disk
func SaveProfiles(store *ProfileStore) error {
	configDir := getConfigDir()
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}

	profilesPath := filepath.Join(configDir, profilesFileName)
	return os.WriteFile(profilesPath, data, 0600)
}

// AddProfile creates a new profile with the given name, nsec, and password
func AddProfile(name, nsec, password string) (*Profile, error) {
	// Decode nsec to get hex private key
	_, decoded, err := nip19.Decode(nsec)
	if err != nil {
		return nil, fmt.Errorf("invalid nsec: %w", err)
	}
	sk := decoded.(string)

	// Get public key
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	// Encrypt the private key
	storedKey, err := encryptKey([]byte(sk), []byte(password))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key: %w", err)
	}

	profile := &Profile{
		ID:           generateProfileID(),
		Name:         name,
		PublicKey:    pk,
		EncryptedKey: storedKey.EncryptedKey,
		Salt:         storedKey.Salt,
		PasswordHash: storedKey.PasswordHash,
		CreatedAt:    time.Now(),
	}

	// Load existing profiles, add new one, save
	store, err := LoadProfiles()
	if err != nil {
		return nil, err
	}

	store.Profiles[profile.ID] = profile
	store.LastUsedProfile = profile.ID

	if err := SaveProfiles(store); err != nil {
		return nil, err
	}

	return profile, nil
}

// DeleteProfile removes a profile by ID
func DeleteProfile(id string) error {
	store, err := LoadProfiles()
	if err != nil {
		return err
	}

	if _, exists := store.Profiles[id]; !exists {
		return fmt.Errorf("profile not found")
	}

	delete(store.Profiles, id)

	// Clear last used if it was deleted
	if store.LastUsedProfile == id {
		store.LastUsedProfile = ""
	}

	return SaveProfiles(store)
}

// UnlockProfile unlocks a profile with the given password and returns the private key
func UnlockProfile(id, password string) (privateKey string, publicKey string, err error) {
	store, err := LoadProfiles()
	if err != nil {
		return "", "", err
	}

	profile, exists := store.Profiles[id]
	if !exists {
		return "", "", fmt.Errorf("profile not found")
	}

	// Create StoredKey from profile data
	storedKey := &StoredKey{
		EncryptedKey: profile.EncryptedKey,
		Salt:         profile.Salt,
		PasswordHash: profile.PasswordHash,
	}

	// Decrypt
	decrypted, err := decryptKey(storedKey, []byte(password))
	if err != nil {
		return "", "", err
	}

	// Update last used
	store.LastUsedProfile = id
	SaveProfiles(store)

	return string(decrypted), profile.PublicKey, nil
}

// GetProfileList returns a list of all profiles for display
func GetProfileList() ([]ProfileInfo, string, error) {
	store, err := LoadProfiles()
	if err != nil {
		return nil, "", err
	}

	var profiles []ProfileInfo
	for _, p := range store.Profiles {
		profiles = append(profiles, ProfileInfo{
			ID:        p.ID,
			Name:      p.Name,
			PublicKey: p.PublicKey,
		})
	}

	return profiles, store.LastUsedProfile, nil
}

// MigrateLegacyKey migrates an old single-key file to the new profile system
func MigrateLegacyKey() error {
	configDir := getConfigDir()
	legacyPath := filepath.Join(configDir, keyFileName)
	profilesPath := filepath.Join(configDir, profilesFileName)

	// Check if legacy key exists and profiles don't
	if _, err := os.Stat(legacyPath); os.IsNotExist(err) {
		return nil // No legacy key to migrate
	}
	if _, err := os.Stat(profilesPath); err == nil {
		return nil // Profiles already exist, don't overwrite
	}

	// Read the legacy key file
	jsonData, err := os.ReadFile(legacyPath)
	if err != nil {
		return err
	}

	var storedKey StoredKey
	if err := json.Unmarshal(jsonData, &storedKey); err != nil {
		return err
	}

	// Create a profile from the legacy key (no pubkey available without password)
	profile := &Profile{
		ID:           generateProfileID(),
		Name:         "Default",
		PublicKey:    "", // Will be set on first unlock
		EncryptedKey: storedKey.EncryptedKey,
		Salt:         storedKey.Salt,
		PasswordHash: storedKey.PasswordHash,
		CreatedAt:    time.Now(),
	}

	store := &ProfileStore{
		LastUsedProfile: profile.ID,
		Profiles:        map[string]*Profile{profile.ID: profile},
	}

	return SaveProfiles(store)
}

// generateProfileID creates a unique profile ID
func generateProfileID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

// listPosts queries posts (kind 1 events) and prints the last 4 posts.
// Returns an error if no posts were found or if all relay connections failed.
func listPosts(pubKey string) error {
	// Use relay list from file or default.
	relays := getRelayList()
	filter := nostr.Filter{
		Authors: []string{pubKey},
		Kinds:   []int{1},
		Limit:   defaultPostLimit,
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeouts.Query)
	defer cancel()

	var events []nostr.Event
	for _, url := range relays {
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			log.Printf("Error connecting to relay %s: %v", url, err)
			continue
		}
		// Use QueryEvents passing a single filter (not a slice)
		evCh, err := relay.QueryEvents(ctx, filter)
		if err != nil {
			log.Printf("Error querying relay %s: %v", url, err)
			relay.Close()
			continue
		}
		// Iterate over the returned channel
	loop:
		for ev := range evCh {
			// Validate timestamp to prevent overflow/invalid data
			if err := ValidateTimestamp(int64(ev.CreatedAt)); err != nil {
				log.Printf("Skipping event with invalid timestamp: %v", err)
				continue
			}
			events = append(events, *ev)
			if len(events) >= 4 {
				break loop
			}
		}
		relay.Close()
		if len(events) >= 4 {
			break
		}
	}

	if len(events) == 0 {
		return fmt.Errorf("no posts found or failed to connect to any relays")
	}

	fmt.Println("Last 4 posts from your profile:")
	for _, ev := range events {
		fmt.Printf("Created: %s\nContent: %s\n\n",
			time.Unix(int64(ev.CreatedAt), 0).Format(time.RFC1123), ev.Content)
	}
	return nil
}

// getFeedPosts returns posts from the global feed for TUI display
func getFeedPosts() ([]tui.FeedPost, error) {
	// Try to get cached events first
	var cachedEvents []*nostr.Event
	cachedCache := getEventCache()
	if cachedCache != nil {
		// Get the most recent cached events
		cachedEvents, _ = cachedCache.GetEventsByPubKey("", 1, 20)
	}

	relays := getRelayList()
	filter := nostr.Filter{
		Kinds: []int{1},
		Limit: feedPostLimit,
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeouts.Query)
	defer cancel()

	var posts []tui.FeedPost
	var eventIDs = make(map[string]bool)

	// First, add cached posts if available
	for _, ev := range cachedEvents {
		if !eventIDs[ev.ID] {
			eventIDs[ev.ID] = true
			posts = append(posts, tui.FeedPost{
				Author:    ev.PubKey,
				Content:   ev.Content,
				CreatedAt: time.Unix(int64(ev.CreatedAt), 0).Format("Jan 2 15:04"),
			})
		}
	}

	// Query relays for fresh data
	for _, url := range relays {
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			continue
		}
		evCh, err := relay.QueryEvents(ctx, filter)
		if err != nil {
			relay.Close()
			continue
		}
		for ev := range evCh {
			// Validate timestamp to prevent overflow/invalid data
			if err := ValidateTimestamp(int64(ev.CreatedAt)); err != nil {
				continue
			}
			// Cache the event for future use (24 hour TTL)
			cachedCache := getEventCache()
			if cachedCache != nil {
				cachedCache.StoreEvent(ev, 24*time.Hour)
			}

			if !eventIDs[ev.ID] {
				eventIDs[ev.ID] = true
				posts = append(posts, tui.FeedPost{
					Author:    ev.PubKey,
					Content:   ev.Content,
					CreatedAt: time.Unix(int64(ev.CreatedAt), 0).Format("Jan 2 15:04"),
				})
			}
			if len(posts) >= 20 {
				break
			}
		}
		relay.Close()
		if len(posts) >= 20 {
			break
		}
	}
	return posts, nil
}

// getDMs returns direct messages for TUI display
func getDMs(privateKey string) ([]tui.FeedPost, error) {
	// Derive public key from private key
	publicKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	relays := getRelayList()
	filter := nostr.Filter{
		Kinds: []int{4}, // DMs are kind 4
		Limit: 50,
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeouts.DMQuery)
	defer cancel()

	var dms []tui.FeedPost
	for _, url := range relays {
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			continue
		}

		evCh, err := relay.QueryEvents(ctx, filter)
		if err != nil {
			relay.Close()
			continue
		}

		for ev := range evCh {
			// Validate timestamp to prevent overflow/invalid data
			if err := ValidateTimestamp(int64(ev.CreatedAt)); err != nil {
				continue
			}
			// Check if this DM is for us or from us
			isForUs := false
			isFromUs := ev.PubKey == publicKey

			for _, tag := range ev.Tags {
				if len(tag) > 1 && tag[0] == "p" && tag[1] == publicKey {
					isForUs = true
					break
				}
			}

			if !isForUs && !isFromUs {
				continue // Skip messages not involving us
			}

			// Decrypt the DM content
			decrypted, err := nip04.Decrypt(ev.Content, []byte(privateKey))
			if err != nil {
				continue // Skip if we can't decrypt
			}

			direction := "from"
			if isFromUs {
				if recipient := ev.Tags.GetFirst([]string{"p"}); recipient != nil && len(*recipient) > 1 {
					pubKeyPart := (*recipient)[1]
					if len(pubKeyPart) >= 8 {
						direction = fmt.Sprintf("to %s", pubKeyPart[:8]+"...")
					} else if len(pubKeyPart) > 0 {
						direction = fmt.Sprintf("to %s", pubKeyPart)
					}
				}
			} else {
				direction = "from"
			}

			dms = append(dms, tui.FeedPost{
				Author:    ev.PubKey,
				Content:   fmt.Sprintf("[DM %s]: %s", direction, decrypted),
				CreatedAt: time.Unix(int64(ev.CreatedAt), 0).Format("Jan 2 15:04"),
			})

			if len(dms) >= 50 {
				break
			}
		}
		relay.Close()
		if len(dms) >= 50 {
			break
		}
	}

	return dms, nil
}

// getReactions returns reactions/replies to a specific event
func getReactions(eventID string) ([]tui.FeedPost, error) {
	relays := getRelayList()
	filter := nostr.Filter{
		Kinds: []int{7, 1}, // Reactions (7) and replies (1)
		Tags:  nostr.TagMap{"e": []string{eventID}},
		Limit: feedPostLimit,
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeouts.Query)
	defer cancel()

	var reactions []tui.FeedPost
	for _, url := range relays {
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			continue
		}

		evCh, err := relay.QueryEvents(ctx, filter)
		if err != nil {
			relay.Close()
			continue
		}

		for ev := range evCh {
			// Validate timestamp to prevent overflow/invalid data
			if err := ValidateTimestamp(int64(ev.CreatedAt)); err != nil {
				continue
			}
			var content string
			if ev.Kind == 7 {
				// Reaction
				content = fmt.Sprintf("[Reacted: %s]", ev.Content)
			} else {
				// Reply
				content = ev.Content
			}

			reactions = append(reactions, tui.FeedPost{
				Author:    ev.PubKey,
				Content:   content,
				CreatedAt: time.Unix(int64(ev.CreatedAt), 0).Format("Jan 2 15:04"),
			})

			if len(reactions) >= 20 {
				break
			}
		}
		relay.Close()
		if len(reactions) >= 20 {
			break
		}
	}

	return reactions, nil
}

// publishPostTUI publishes a note using either NIP-46 or local key
// Returns error if publishing failed completely. Logs success details internally.
func publishPostTUI(content string) error {
	var event nostr.Event
	event.Kind = 1
	event.Content = content
	event.CreatedAt = nostr.Now()
	event.Tags = nostr.Tags{}

	relays := getRelayList()

	// If NIP-46 session is active, use it
	if nip46Session := getNIP46Session(); nip46Session != nil {
		event.PubKey = nip46Session.UserPublicKey
		ctx, cancel := context.WithTimeout(context.Background(), timeouts.SignEvent)
		defer cancel()
		if err := nip46Session.SignEvent(ctx, &event); err != nil {
			return fmt.Errorf("remote signing failed: %w", err)
		}
	} else {
		// Use local key
		if localPrivateKey := getLocalPrivateKey(); localPrivateKey == "" {
			return fmt.Errorf("no active session or local key")
		} else {
			event.PubKey, _ = nostr.GetPublicKey(localPrivateKey)
			event.Sign(localPrivateKey)
		}
	}

	success := 0
	var failedRelays []string
	for _, url := range relays {
		ctx, cancel := context.WithTimeout(context.Background(), timeouts.Publish)
		defer cancel()
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			failedRelays = append(failedRelays, url)
			continue
		}

		if err := relay.Publish(ctx, event); err == nil {
			success++
		} else {
			failedRelays = append(failedRelays, url)
		}
		relay.Close()
	}

	if success == 0 {
		return fmt.Errorf("failed to publish to any relay")
	}

	// Log success details for debugging
	if len(failedRelays) > 0 {
		log.Printf("Published to %d/%d relays. Failed: %v", success, len(relays), failedRelays)
	} else {
		log.Printf("Published successfully to all %d relays", success)
	}

	return nil
}


// getProfile queries for a kind 0 (profile) event.
// Returns an error if the profile is not found or if all relay connections failed.
func getProfile(pubKey string) error {
	// Use relay list from file or default.
	relays := getRelayList()
	filter := nostr.Filter{
		Authors: []string{pubKey},
		Kinds:   []int{0},
		Limit:   1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeouts.Query)
	defer cancel()

	var profileEvent *nostr.Event
	for _, url := range relays {
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			log.Printf("Error connecting to relay %s: %v", url, err)
			continue
		}
		evCh, err := relay.QueryEvents(ctx, filter)
		if err != nil {
			log.Printf("Error querying relay %s: %v", url, err)
			relay.Close()
			continue
		}
		for ev := range evCh {
			// Validate timestamp
			if err := ValidateTimestamp(int64(ev.CreatedAt)); err != nil {
				continue
			}
			profileEvent = ev
			break
		}
		relay.Close()
		if profileEvent != nil {
			break
		}
	}

	if profileEvent == nil {
		return fmt.Errorf("profile not found")
	}

	fmt.Println("Your profile:")
	fmt.Println(profileEvent.Content)
	return nil
}

// editProfile publishes a new kind 0 (profile) event with the updated profile info.
func editProfile(privateKey, newContent, pubKey string, relays []string) error {
	event := nostr.Event{
		PubKey:    pubKey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      0,
		Content:   newContent,
		Tags:      nostr.Tags{},
	}
	if err := event.Sign(privateKey); err != nil {
		return fmt.Errorf("failed to sign profile event: %w", err)
	}
	ctx := context.Background()
	pool := nostr.NewSimplePool(ctx)
	for _, relayURL := range relays {
		r, err := pool.EnsureRelay(relayURL)
		if err != nil {
			log.Printf("Failed to add relay %s: %v", relayURL, err)
			continue
		}
		err = r.Publish(ctx, event)
		if err == nil {
			fmt.Printf("Successfully published profile update to relay: %s\n", r.URL)
		} else {
			fmt.Printf("Failed to publish to relay %s: %v\n", r.URL, err)
		}
	}
	return nil
}

// registerAsHandler registers the app as a handler for specific kinds.
func registerAsHandler(privateKey, publicKey string, kinds []int, platforms map[string]string) error {
	// Create a kind 1984 event for handler registration
	event := nostr.Event{
		PubKey:    publicKey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1984,
		Tags:      nostr.Tags{},
		Content:   "",
	}

	// Add tags for supported kinds and platforms
	for _, kind := range kinds {
		event.Tags = append(event.Tags, nostr.Tag{"k", fmt.Sprintf("%d", kind)})
	}
	for platform, url := range platforms {
		event.Tags = append(event.Tags, nostr.Tag{"p", platform, url})
	}

	// Sign the event
	if err := event.Sign(privateKey); err != nil {
		return fmt.Errorf("failed to sign handler registration event: %w", err)
	}

	// Publish the event to relays
	ctx := context.Background()
	relays := getRelayList()
	pool := nostr.NewSimplePool(ctx)
	for _, relayURL := range relays {
		relay, err := pool.EnsureRelay(relayURL)
		if err != nil {
			log.Printf("Failed to connect to relay %s: %v", relayURL, err)
			continue
		}

		if err := relay.Publish(ctx, event); err != nil {
			log.Printf("Failed to publish to relay %s: %v", relay.URL, err)
		} else {
			fmt.Printf("Handler registration published to relay: %s\n", relay.URL)
		}

		relay.Close()
	}
	return nil
}

// recommendApp publishes a recommendation for an app for a specific kind.
func recommendApp(privateKey, publicKey, handlerPubKey, handlerDIdentifier string, kind int, relayHint, platform string) error {
	// Create a kind 1985 event for app recommendation
	event := nostr.Event{
		PubKey:    publicKey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1985,
		Tags: nostr.Tags{
			{"a", fmt.Sprintf("%s:%s:%d", handlerPubKey, handlerDIdentifier, kind)},
			{"p", platform},
		},
		Content: relayHint,
	}

	// Sign the event
	if err := event.Sign(privateKey); err != nil {
		return fmt.Errorf("failed to sign app recommendation event: %w", err)
	}

	// Publish the event to relays
	ctx := context.Background()
	relays := getRelayList()
	pool := nostr.NewSimplePool(ctx)
	for _, relayURL := range relays {
		relay, err := pool.EnsureRelay(relayURL)
		if err != nil {
			log.Printf("Failed to connect to relay %s: %v", relayURL, err)
			continue
		}

		if err := relay.Publish(ctx, event); err != nil {
			log.Printf("Failed to publish to relay %s: %v", relay.URL, err)
		} else {
			fmt.Printf("App recommendation published to relay: %s\n", relay.URL)
		}

		relay.Close()
	}
	return nil
}

// findHandlers queries relays for handlers of a specific kind.
func findHandlers(kind int) ([]struct {
	PubKey         string
	SupportedKinds []int
	Platforms      map[string]string
}, error) {
	// Use relay list from file or default
	relays := getRelayList()
	filter := nostr.Filter{
		Kinds: []int{1984},
		Tags:  nostr.TagMap{"k": []string{fmt.Sprintf("%d", kind)}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeouts.Query)
	defer cancel()

	var handlers []struct {
		PubKey         string
		SupportedKinds []int
		Platforms      map[string]string
	}

	for _, url := range relays {
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			log.Printf("Error connecting to relay %s: %v", url, err)
			continue
		}

		evCh, err := relay.QueryEvents(ctx, filter)
		if err != nil {
			log.Printf("Error querying relay %s: %v", url, err)
			relay.Close()
			continue
		}

		for ev := range evCh {
			// Validate timestamp to prevent overflow/invalid data
			if err := ValidateTimestamp(int64(ev.CreatedAt)); err != nil {
				continue
			}
			handler := struct {
				PubKey         string
				SupportedKinds []int
				Platforms      map[string]string
			}{
				PubKey:    ev.PubKey,
				Platforms: make(map[string]string),
			}

			for _, tag := range ev.Tags {
				if tag[0] == "k" {
					kind, err := strconv.Atoi(tag[1])
					if err == nil {
						handler.SupportedKinds = append(handler.SupportedKinds, kind)
					}
				} else if tag[0] == "p" && len(tag) > 2 {
					handler.Platforms[tag[1]] = tag[2]
				}
			}
			handlers = append(handlers, handler)
		}
		relay.Close()
	}
	return handlers, nil
}

func payInvoiceNWC(invoice string, password []byte) error {
	// 1. Get NWC URI
	uriStr, err := getNWCURI(password)
	if err != nil {
		return fmt.Errorf("failed to get NWC URI (use -nwc to set it): %w", err)
	}
	// Parse URI: nostr+walletconnect://<pubkey>?relay=<relay>&secret=<secret>
	u, err := url.Parse(uriStr)
	if err != nil {
		return fmt.Errorf("invalid NWC URI: %w", err)
	}
	if u.Scheme != "nostr+walletconnect" {
		return fmt.Errorf("invalid scheme, expected nostr+walletconnect")
	}

	walletPubKey := u.Hostname() // authority is pubkey
	relayURL := u.Query().Get("relay")
	secret := u.Query().Get("secret")
	if walletPubKey == "" || relayURL == "" || secret == "" {
		return fmt.Errorf("incomplete NWC URI")
	}

	// 2. Connect to Relay
	ctx := context.Background()
	relay, err := nostr.RelayConnect(ctx, relayURL)
	if err != nil {
		return fmt.Errorf("failed to connect to NWC relay: %w", err)
	}
	defer relay.Close()

	// 3. Prepare NWC Encrypted Content (NIP-04)
	// Current standard for NWC is specific.
	// Request: kind 23194
	// Content: {"method": "pay_invoice", "params": {"invoice": "..."}} encrypted

	requestPayload := map[string]interface{}{
		"method": "pay_invoice",
		"params": map[string]interface{}{
			"invoice": invoice,
		},
	}
	jsonPayload, _ := json.Marshal(requestPayload)

	// Compute shared secret
	ss, err := nip04.ComputeSharedSecret(walletPubKey, secret)
	if err != nil {
		return fmt.Errorf("failed to compute shared secret: %w", err)
	}

	encryptedContent, err := nip04.Encrypt(string(jsonPayload), ss)
	if err != nil {
		return fmt.Errorf("failed to encrypt request: %w", err)
	}

	// 4. Publish Request
	pk, _ := nostr.GetPublicKey(secret)
	event := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      23194,
		Tags:      nostr.Tags{{"p", walletPubKey}},
		Content:   encryptedContent,
	}
	event.Sign(secret)

	if err := relay.Publish(ctx, event); err != nil {
		return fmt.Errorf("failed to publish request: %w", err)
	}

	//Ideally we should listen for response (kind 23195), but for simplicity:
	fmt.Println("NWC Request sent! Payment should happen shortly.")
	return nil
}

// NWC Helpers

// NWC URI storage functions - encrypted for security

func saveNWCURI(uri string, password []byte) error {
	configDir := getConfigDir()
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}

	// Encrypt the URI using the same mechanism as private keys
	storedKey, err := encryptKey([]byte(uri), password)
	if err != nil {
		return fmt.Errorf("failed to encrypt NWC URI: %w", err)
	}

	// Convert to JSON
	jsonData, err := json.Marshal(storedKey)
	if err != nil {
		return err
	}

	// Save to encrypted file
	path := filepath.Join(configDir, "nwc.enc")
	return os.WriteFile(path, jsonData, 0600)
}

func getNWCURI(password []byte) (string, error) {
	configDir := getConfigDir()
	
	// Try encrypted file first
	encPath := filepath.Join(configDir, "nwc.enc")
	if _, err := os.Stat(encPath); err == nil {
		jsonData, err := os.ReadFile(encPath)
		if err != nil {
			return "", err
		}

		var storedKey StoredKey
		if err := json.Unmarshal(jsonData, &storedKey); err != nil {
			return "", err
		}

		decrypted, err := decryptKey(&storedKey, password)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt NWC URI: %w", err)
		}

		return string(decrypted), nil
	}

	// Fall back to legacy plaintext file for migration
	txtPath := filepath.Join(configDir, "nwc.txt")
	data, err := os.ReadFile(txtPath)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}


// resolveLud16 fetches the callback from a Lightning Address (username@domain)
func resolveLud16(lud16 string) (string, error) {
	parts := strings.Split(lud16, "@")
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid lightning address format")
	}
	username, domain := parts[0], parts[1]
	url := fmt.Sprintf("https://%s/.well-known/lnurlp/%s", domain, username)

	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("lnurl request failed: %s", resp.Status)
	}

	var data struct {
		Callback string `json:"callback"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	return data.Callback, nil
}

func fetchLightningInvoice(callback string, amountSats int64) (string, error) {
	// Amount in millisats
	amountMillisats := amountSats * 1000

	// Check if callback already has query params
	separator := "?"
	if strings.Contains(callback, "?") {
		separator = "&"
	}

	url := fmt.Sprintf("%s%samount=%d", callback, separator, amountMillisats)
	resp, err := http.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var data struct {
		PR string `json:"pr"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return "", err
	}
	if data.PR == "" {
		return "", fmt.Errorf("no payment request in response")
	}
	return data.PR, nil
}

func extractLud16(pubKey string, relays []string) (string, error) {
	filter := nostr.Filter{
		Authors: []string{pubKey},
		Kinds:   []int{0},
		Limit:   1,
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeouts.Query)
	defer cancel()

	var profileEvent *nostr.Event

	// Poor man's pool query for single event
	for _, url := range relays {
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			continue
		}

		ch, err := relay.QueryEvents(ctx, filter)
		if err != nil {
			relay.Close()
			continue
		}

		for ev := range ch {
			profileEvent = ev
			break
		}
		relay.Close()
		if profileEvent != nil {
			break
		}
	}

	if profileEvent == nil {
		return "", fmt.Errorf("profile not found")
	}

	var profile struct {
		LUD16 string `json:"lud16"`
	}
	if err := json.Unmarshal([]byte(profileEvent.Content), &profile); err != nil {
		return "", err
	}
	if profile.LUD16 == "" {
		return "", fmt.Errorf("user has no lightning address (lud16)")
	}
	return profile.LUD16, nil
}

// runTipCommand handles the CLI tip command, returning errors instead of exiting.
func runTipCommand(tipAmount int64, tipUser, password string) error {
	// Validate tip amount
	if tipAmount < minTipSats {
		return fmt.Errorf("tip amount too small: minimum is %d sat(s)", minTipSats)
	}
	if tipAmount > maxTipSats {
		return fmt.Errorf("tip amount too large: maximum is %d sat(s). For larger tips, please use your wallet directly", maxTipSats)
	}

	if tipUser == "" {
		return fmt.Errorf("please specify a user to tip with -user")
	}

	target := tipUser
	var hexPubKey string
	var lud16 string

	// Check if it is a lightning address
	if strings.Contains(target, "@") {
		lud16 = target
	} else {
		// Assume it's a pubkey (npub or hex)
		if strings.HasPrefix(target, "npub") {
			_, decoded, err := nip19.Decode(target)
			if err != nil {
				return fmt.Errorf("invalid npub: %w", err)
			}
			hexPubKey = decoded.(string)
		} else {
			hexPubKey = target
		}

		// Resolve LUD16 from profile
		fmt.Println("Resolving Lightning Address from Nostr profile...")
		relays := getRelayList()
		l, err := extractLud16(hexPubKey, relays)
		if err != nil {
			return fmt.Errorf("could not find lightning address for user: %w", err)
		}
		lud16 = l
	}

	fmt.Printf("Found lightning address: %s\n", lud16)

	// Resolve Callback
	callback, err := resolveLud16(lud16)
	if err != nil {
		return fmt.Errorf("failed to resolve lightning address: %w", err)
	}

	// Fetch Invoice
	fmt.Printf("Fetching invoice for %d sats...\n", tipAmount)
	invoice, err := fetchLightningInvoice(callback, tipAmount)
	if err != nil {
		return fmt.Errorf("failed to fetch invoice: %w", err)
	}

	// Pay
	fmt.Println("Paying invoice via NWC...")
	if err := payInvoiceNWC(invoice, []byte(password)); err != nil {
		return fmt.Errorf("payment failed: %w", err)
	}
	return nil
}

// decodePrivateKey decodes a private key (nsec or hex) and returns (sk, pk, error).
func decodePrivateKey(privateKey string) (sk, pk string, err error) {
	if strings.HasPrefix(privateKey, "nsec") {
		_, decoded, decodeErr := nip19.Decode(privateKey)
		if decodeErr != nil {
			return "", "", fmt.Errorf("invalid nsec key: %w", decodeErr)
		}
		sk = decoded.(string)
	} else {
		sk = privateKey
	}
	pk, err = nostr.GetPublicKey(sk)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive public key: %w", err)
	}
	return sk, pk, nil
}

// runRegisterHandlerCommand handles the NIP-89 handler registration CLI command.
func runRegisterHandlerCommand(sk, pk, kindStrsRaw, urlTemplate, platform string) error {
	kindStrs := strings.Split(kindStrsRaw, ",")
	var kinds []int
	for _, kindStr := range kindStrs {
		kind, err := strconv.Atoi(strings.TrimSpace(kindStr))
		if err != nil {
			return fmt.Errorf("invalid kind: %s", kindStr)
		}
		kinds = append(kinds, kind)
	}

	if urlTemplate == "" {
		return fmt.Errorf("URL template is required for handler registration (use -url)")
	}

	platforms := map[string]string{
		platform: urlTemplate,
	}

	return withLoading("Registering handler", func() error {
		return registerAsHandler(sk, pk, kinds, platforms)
	})
}

// runRecommendCommand handles the NIP-89 recommend CLI command.
func runRecommendCommand(sk, pk, recommendRaw, relaysRaw string) error {
	parts := strings.Split(recommendRaw, ":")
	if len(parts) != 3 {
		return fmt.Errorf("invalid recommend format. Use: pubkey:d-identifier:kind")
	}

	handlerPubKey := parts[0]
	handlerDIdentifier := parts[1]
	kind, err := strconv.Atoi(parts[2])
	if err != nil {
		return fmt.Errorf("invalid kind: %s", parts[2])
	}

	var relayHint string
	if relaysRaw != "" {
		relays := strings.Split(relaysRaw, ",")
		relayHint = strings.TrimSpace(relays[0])
	} else {
		relayList := getRelayList()
		if len(relayList) > 0 {
			relayHint = relayList[0]
		}
	}

	return withLoading("Publishing recommendation", func() error {
		return recommendApp(sk, pk, handlerPubKey, handlerDIdentifier, kind, relayHint, "web")
	})
}

// runDMsCommand loads and displays direct messages.
func runDMsCommand(sk string) error {
	return withLoading("Loading DMs", func() error {
		dms, err := getDMs(sk)
		if err != nil {
			return fmt.Errorf("failed to load DMs: %w", err)
		}
		fmt.Println("Your recent direct messages:")
		for _, dm := range dms {
			fmt.Printf("%s (%s): %s\n\n", dm.Author[:16]+"...", dm.CreatedAt, dm.Content)
		}
		return nil
	})
}

// runRepliesCommand loads and displays replies/reactions to an event.
func runRepliesCommand(eventID string) error {
	return withLoading("Loading replies", func() error {
		replies, err := getReactions(eventID)
		if err != nil {
			return fmt.Errorf("failed to load replies: %w", err)
		}
		fmt.Printf("Replies and reactions to event %s:\n", eventID)
		for _, reply := range replies {
			fmt.Printf("%s (%s): %s\n\n", reply.Author[:16]+"...", reply.CreatedAt, reply.Content)
		}
		return nil
	})
}

// runUpdateProfileCommand updates the user's profile.
func runUpdateProfileCommand(sk, pk, updateJSON, relaysRaw string) error {
	var relays []string
	if relaysRaw != "" {
		relays = strings.Split(relaysRaw, ",")
		for i := range relays {
			relays[i] = strings.TrimSpace(relays[i])
		}
	} else {
		relays = getRelayList()
	}
	return withLoading("Updating profile", func() error {
		return editProfile(sk, updateJSON, pk, relays)
	})
}

// runFindHandlersCommand finds and displays NIP-89 handlers for a kind.
func runFindHandlersCommand(kind int) error {
	return withLoading("Finding handlers", func() error {
		handlers, err := findHandlers(kind)
		if err != nil {
			return err
		}

		if len(handlers) == 0 {
			fmt.Printf("No handlers found for kind %d\n", kind)
			return nil
		}

		fmt.Printf("Found %d handlers for kind %d:\n", len(handlers), kind)
		for i, handler := range handlers {
			fmt.Printf("%d. PubKey: %s\n", i+1, handler.PubKey)
			fmt.Printf("   Supported kinds: %v\n", handler.SupportedKinds)
			fmt.Printf("   Platforms:\n")
			for platform, url := range handler.Platforms {
				fmt.Printf("     - %s: %s\n", platform, url)
			}
			fmt.Println()
		}
		return nil
	})
}

// readPassword reads the encryption password from env or terminal.
func readPassword() (string, error) {
	// Check for password in environment variable first (for testing/automation)
	if password := os.Getenv("HOOT_PASSWORD"); password != "" {
		return password, nil
	}

	// Read encryption password without echoing
	fmt.Print("Enter encryption password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", fmt.Errorf("error reading password: %w", err)
	}
	fmt.Println("") // newline after password input
	return string(bytePassword), nil
}

// runNWCSetup saves an NWC URI for tipping.
func runNWCSetup(nwcURI, password string) error {
	if err := saveNWCURI(nwcURI, []byte(password)); err != nil {
		return fmt.Errorf("failed to save NWC URI: %w", err)
	}
	fmt.Println("NWC URI saved successfully (encrypted).")
	return nil
}

// runStoreKeyCommand stores a new private key.
func runStoreKeyCommand(key, password string) error {
	if key == "" {
		return fmt.Errorf("must provide a private key with -k when using -s")
	}
	return withLoading("Storing key", func() error {
		return saveKey(key, []byte(password))
	})
}

// loadAndDecodeKey loads the encrypted key and decodes it to sk/pk.
func loadAndDecodeKey(password string) (sk, pk string, err error) {
	var privateKey string
	if err := withLoading("Loading key", func() error {
		var loadErr error
		privateKey, loadErr = loadKey([]byte(password))
		return loadErr
	}); err != nil {
		return "", "", fmt.Errorf("failed to load private key: %w", err)
	}

	return decodePrivateKey(privateKey)
}

func main() {
	// Initialize cache for improved performance
	configDir := getConfigDir()
	eventCache, err := cache.New(configDir)
	if err != nil {
		log.Printf("Warning: failed to initialize cache: %v", err)
	} else {
		defer eventCache.Close()
		// Start periodic cleanup every hour
		eventCache.StartCleanup(1 * time.Hour)
	}

	// Define command-line flags
	messagePtr := flag.String("m", "", "Message to post (optional)")
	keyPtr := flag.String("k", "", "Private key to store (use with -s)")
	storePtr := flag.Bool("s", false, "Store a new private key")
	relaysPtr := flag.String("r", "", "Comma-separated list of relay URLs")
	listPtr := flag.Bool("l", false, "List last 4 posts from your profile")
	profilePtr := flag.Bool("p", false, "Retrieve and display profile info")
	updatePtr := flag.String("u", "", "Update profile info")
	dmsPtr := flag.Bool("dms", false, "View direct messages")
	repliesPtr := flag.String("replies", "", "View replies/reactions for a specific event ID")
	versionPtr := flag.Bool("version", false, "Display the version")

	// NWC / Tipping flags
	nwcPtr := flag.String("nwc", "", "Set NWC URI for tipping")
	tipPtr := flag.Int64("tip", 0, "Amount in sats to tip (requires -user)")
	tipUserPtr := flag.String("user", "", "User to tip (npub or hex pubkey)")

	// NIP-89 related flags
	registerHandlerPtr := flag.String("register-handler", "", "Register as handler for kinds (comma-separated)")
	platformPtr := flag.String("platform", "web", "Platform for handler (web, ios, android)")
	urlTemplatePtr := flag.String("url-template", "", "URL template for handler (e.g. https://example.com/e/<bech32>)")
	recommendPtr := flag.String("recommend", "", "Recommend an app for a kind (format: pubkey:d-identifier:kind)")
	findHandlersPtr := flag.Int("find-handlers", 0, "Find handlers for a specific kind")

	flag.Parse()

	// Handle version flag
	if *versionPtr {
		fmt.Printf("nostr-cli version %s\n", version)
		return
	}

	// Launch TUI if no flags provided
	if flag.NFlag() == 0 && flag.NArg() == 0 {
		// Migrate legacy key file to profile system if needed
		if err := MigrateLegacyKey(); err != nil {
			log.Printf("Warning: failed to migrate legacy key: %v", err)
		}

		cfg := tui.Config{
			HasKey: func() bool {
				configDir := getConfigDir()
				keyPath := filepath.Join(configDir, keyFileName)
				_, err := os.Stat(keyPath)
				return !os.IsNotExist(err)
			},
			OnLoadKey: func(password string) (string, string, error) {
				privKey, err := loadKey([]byte(password))
				if err != nil {
					return "", "", err
				}
				var sk string
				if strings.HasPrefix(privKey, "nsec") {
					_, decoded, err := nip19.Decode(privKey)
					if err != nil {
						return "", "", err
					}
					sk = decoded.(string)
				} else {
					sk = privKey
				}
				pk, err := nostr.GetPublicKey(sk)
				if err != nil {
					return "", "", err
				}
				// Cache for posting
				setLocalPrivateKey(sk)
				return sk, pk, nil
			},
			OnResetKey: func() error {
				configDir := getConfigDir()
				keyPath := filepath.Join(configDir, keyFileName)
				return os.Remove(keyPath)
			},
			OnLogin: func(nsec string, password string, save bool) (string, error) {
				_, decoded, err := nip19.Decode(nsec)
				if err != nil {
					return "", err
				}
				sk := decoded.(string)
				pk, err := nostr.GetPublicKey(sk)
				if err != nil {
					return "", err
				}

				if save {
					if err := saveKey(sk, []byte(password)); err != nil {
						return "", err
					}
				}

				// Cache for posting
				setLocalPrivateKey(sk)
				return pk, nil
			},
			OnPost:        publishPostTUI,
			OnLoadFeed:    getFeedPosts,
			OnLoadDMs:     getDMs,
			OnLoadReplies: getReactions,
			OnLoadRelays: func() ([]string, error) {
				return loadRelays() // Uses existing helper
			},
			OnSaveRelays: func(relays []string) error {
				configDir := getConfigDir()
				relayPath := filepath.Join(configDir, "relays.txt")
				// Ensure directory exists
				if err := os.MkdirAll(configDir, 0700); err != nil {
					return err
				}
				data := strings.Join(relays, "\n")
				return os.WriteFile(relayPath, []byte(data), 0600)
			},
			OnInitQR: func() (string, error) {
				// Initialize NIP-46 session
				relays := getRelayList()
				relayURL := relays[0] // Use first configured relay
				uri, session, err := nip46.GenerateConnectURI(relayURL, "Hoot")
				if err != nil {
					return "", err
				}
				setNIP46Session(session)
				return uri, nil
			},
			OnCheckQR: func() (string, error) {
				if nip46Session := getNIP46Session(); nip46Session == nil {
					return "", fmt.Errorf("session not initialized")
				}
				// Wait for connection
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()

				session := getNIP46Session()
				if err := session.WaitForConnection(ctx); err != nil {
					return "", err
				}

				// Get public key
				pubKey, err := session.GetPublicKey(ctx)
				if err != nil {
					return "", err
				}

				return pubKey, nil
			},
			// Profile callbacks
			OnListProfiles: func() ([]tui.ProfileInfo, string, error) {
				profiles, lastUsed, err := GetProfileList()
				if err != nil {
					return nil, "", err
				}
				// Convert to TUI ProfileInfo
				var tuiProfiles []tui.ProfileInfo
				for _, p := range profiles {
					tuiProfiles = append(tuiProfiles, tui.ProfileInfo{
						ID:        p.ID,
						Name:      p.Name,
						PublicKey: p.PublicKey,
					})
				}
				return tuiProfiles, lastUsed, nil
			},
			OnSelectProfile: func(id, password string) (string, string, error) {
				privKey, pubKey, err := UnlockProfile(id, password)
				if err != nil {
					return "", "", err
				}
				// Cache for posting
				setLocalPrivateKey(privKey)
				return privKey, pubKey, nil
			},
			OnAddProfile: func(name, nsec, password string) (string, error) {
				profile, err := AddProfile(name, nsec, password)
				if err != nil {
					return "", err
				}
				// Cache the private key for posting
				_, decoded, _ := nip19.Decode(nsec)
				setLocalPrivateKey(decoded.(string))
				return profile.PublicKey, nil
			},
			OnDeleteProfile: DeleteProfile,
		}
		if err := tui.Run(cfg); err != nil {
			log.Fatalf("TUI error: %v", err)
		}
		return
	}

	// Read encryption password without echoing
	password, err := readPassword()
	if err != nil {
		log.Fatalf("%v", err)
	}

	// Handle NWC setup
	if *nwcPtr != "" {
		if err := runNWCSetup(*nwcPtr, password); err != nil {
			log.Fatalf("%v", err)
		}
		return
	}

	// Handle Tipping
	if *tipPtr > 0 {
		if err := runTipCommand(*tipPtr, *tipUserPtr, password); err != nil {
			log.Fatalf("%v", err)
		}
		return
	}

	// Check if key exists
	keyPath := filepath.Join(configDir, keyFileName)
	_, err = os.Stat(keyPath)
	keyExists := !os.IsNotExist(err)

	// Interactive Login if no key found and no store flag
	// Use flag.NFlag() == 0 to assume interactive mode if no flags provided
	if !keyExists && !*storePtr && *messagePtr == "" && *updatePtr == "" && !*profilePtr && !*listPtr && *nwcPtr == "" && *tipPtr == 0 {
		fmt.Println("No private key found.")
		fmt.Print("Enter your Nostr private key (nsec) to login: ")
		var input string
		fmt.Scanln(&input)
		if input != "" {
			*keyPtr = strings.TrimSpace(input)
			*storePtr = true
			fmt.Println("You will now be asked to create a password to encrypt this key.")
		}
	}

	// Save a new key action with loading bar.
	if *storePtr {
		if err := runStoreKeyCommand(*keyPtr, password); err != nil {
			log.Fatalf("%v", err)
		}
		return
	}

	// Load and decode private key
	sk, pk, err := loadAndDecodeKey(password)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// Handle NIP-89 register-handler command
	if *registerHandlerPtr != "" {
		if err := runRegisterHandlerCommand(sk, pk, *registerHandlerPtr, *urlTemplatePtr, *platformPtr); err != nil {
			log.Fatalf("%v", err)
		}
		return
	}

	// Handle NIP-89 recommend command
	if *recommendPtr != "" {
		if err := runRecommendCommand(sk, pk, *recommendPtr, *relaysPtr); err != nil {
			log.Fatalf("%v", err)
		}
		return
	}

	// Handle NIP-89 find-handlers command
	if *findHandlersPtr > 0 {
		if err := runFindHandlersCommand(*findHandlersPtr); err != nil {
			log.Fatalf("%v", err)
		}
		return
	}

	relaysFromFile := getRelayList()
	fmt.Println("Loaded relays:")
	for _, r := range relaysFromFile {
		fmt.Println(" -", r)
	}
	// *****************************************************

	// Check if a command was provided (e.g. "profile")
	if flag.NArg() > 0 && flag.Arg(0) == "profile" {
		err := withLoading("Retrieving profile", func() error {
			return getProfile(pk)
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Handle list posts action with loading.
	if *listPtr {
		err := withLoading("Listing posts", func() error {
			return listPosts(pk)
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Handle DMs action with loading.
	if *dmsPtr {
		if err := runDMsCommand(sk); err != nil {
			log.Fatalf("%v", err)
		}
		return
	}

	// Handle replies action with loading.
	if *repliesPtr != "" {
		if err := runRepliesCommand(*repliesPtr); err != nil {
			log.Fatalf("%v", err)
		}
		return
	}

	// If no message is provided, just show the public key and exit.
	if *messagePtr == "" && !*profilePtr && *updatePtr == "" {
		npub, _ := nip19.EncodePublicKey(pk)
		fmt.Printf("Your Nostr public key (npub): %s\n", npub)
		return
	}

	// Handle profile view action with loading.
	if *profilePtr {
		err := withLoading("Retrieving profile", func() error {
			return getProfile(pk)
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// Handle profile update action with loading.
	if *updatePtr != "" {
		if err := runUpdateProfileCommand(sk, pk, *updatePtr, *relaysPtr); err != nil {
			log.Fatalf("%v", err)
		}
		return
	}

	// Publish a message
	if *messagePtr != "" {
		if err := runPublishCommand(sk, pk, *messagePtr, *relaysPtr); err != nil {
			log.Fatalf("%v", err)
		}
		return
	}
}

// runPublishCommand signs and publishes a text note to relays.
func runPublishCommand(sk, pk, content, relaysRaw string) error {
	event := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1,
		Content:   content,
		Tags:      nostr.Tags{},
	}
	words := strings.Fields(event.Content)
	for _, word := range words {
		if strings.HasPrefix(word, "#") {
			tag := strings.Trim(word, "#.,!?:;")
			event.Tags = append(event.Tags, []string{"t", tag})
		}
	}
	if err := event.Sign(sk); err != nil {
		return fmt.Errorf("failed to sign event: %w", err)
	}

	var relays []string
	if relaysRaw != "" {
		relays = strings.Split(relaysRaw, ",")
		for i := range relays {
			relays[i] = strings.TrimSpace(relays[i])
		}
	} else {
		relays = getRelayList()
	}

	return withLoading("Publishing post", func() error {
		ctx := context.Background()
		pool := nostr.NewSimplePool(ctx)
		for _, relayURL := range relays {
			relay, err := pool.EnsureRelay(relayURL)
			if err != nil {
				log.Printf("Failed to add relay %s: %v", relayURL, err)
				continue
			}
			_ = relay
		}
		pool.Relays.Range(func(key string, relay *nostr.Relay) bool {
			err := relay.Publish(ctx, event)
			if err == nil {
				fmt.Printf("Successfully published to relay: %s\n", relay.URL)
			} else {
				fmt.Printf("Failed to publish to relay %s: %v\n", relay.URL, err)
			}
			return true
		})
		return nil
	})
}
