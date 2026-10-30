package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"hoot/cache"
	"hoot/internal/relay"
	"hoot/nip46"
	"hoot/tui"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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
)

const (
	appName          = "hoot"
	keyFileName      = "nostr_key.enc"
	profilesFileName = "profiles.json"
)

// version, commit, and date are set at build time by goreleaser via
// ldflags: -X main.version=... -X main.commit=... -X main.date=...
// When built with plain `go build`, they keep their defaults.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
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

// Global NIP-46 session and local key
var nip46Session *nip46.Session
var localPrivateKey string

// endRemoteSession closes and forgets any NIP-46 session. publishPostTUI
// prefers nip46Session over localPrivateKey, so a session left over from an
// abandoned QR attempt (or a previous Amber login) would otherwise hijack
// signing for a local-key login.
func endRemoteSession() {
	if nip46Session != nil {
		nip46Session.Close()
		nip46Session = nil
	}
}

// useLocalKey switches the process to signing with a local hex key.
func useLocalKey(sk string) {
	endRemoteSession()
	localPrivateKey = sk
}

// Global cache instance for improved performance
var eventCache *cache.Cache

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
				fmt.Fprintf(os.Stderr, "\r%s %c", message, spinner[i%len(spinner)])
				i++
				time.Sleep(100 * time.Millisecond)
			}
		}
	}()
	err := fn()
	done <- true
	// Clear the loading line
	fmt.Fprintf(os.Stderr, "\r%s done\n", message)
	return err
}

// hashPassword creates a bcrypt hash of the given password.
func hashPassword(password string) (string, error) {
	hashedBytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
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

func deriveKey(password []byte, salt []byte) ([]byte, error) {
	return scrypt.Key(password, salt, 32768, 8, 1, 32)
}

func encryptKey(key []byte, password []byte) (*StoredKey, error) {
	// Generate 32 random bytes for salt.
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	// Derive encryption key from password and salt
	derivedKey, err := deriveKey(password, salt)
	if err != nil {
		return nil, err
	}

	// Generate 24 random bytes for nonce.
	var nonce [24]byte
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

	if len(storedKey.EncryptedKey) < 24+secretbox.Overhead {
		return nil, fmt.Errorf("stored key is corrupt (too short)")
	}

	// Prepare nonce and secret key
	var nonce [24]byte
	copy(nonce[:], storedKey.EncryptedKey[:24])
	var secretKey [32]byte
	copy(secretKey[:], derivedKey[:32])

	// Decrypt the key
	decryptedKey, ok := secretbox.Open(nil, storedKey.EncryptedKey[24:], &nonce, &secretKey)
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

// normalizePrivKey accepts a private key as either nsec or 64-char hex and
// returns it as hex. Keys stored via the CLI (`hoot -s -k nsec1...`) are
// saved verbatim, so anything that decrypts a stored key must go through
// this before signing.
func normalizePrivKey(key string) (string, error) {
	key = strings.TrimSpace(key)
	if strings.HasPrefix(key, "nsec") {
		_, decoded, err := nip19.Decode(key)
		if err != nil {
			return "", fmt.Errorf("invalid nsec: %w", err)
		}
		sk, ok := decoded.(string)
		if !ok {
			return "", fmt.Errorf("invalid nsec payload")
		}
		return sk, nil
	}
	if !nostr.IsValid32ByteHex(key) {
		return "", fmt.Errorf("stored key is neither nsec nor 64-char hex")
	}
	return key, nil
}

// UnlockProfile unlocks a profile with the given password and returns the
// private key (always hex) and public key.
//
// Profiles created by MigrateLegacyKey have no PublicKey (it can't be
// derived without the password) and may hold an nsec rather than hex. Both
// are fixed up here on first unlock, and the derived pubkey is persisted so
// the login screen can show it next time.
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

	sk, err := normalizePrivKey(string(decrypted))
	if err != nil {
		return "", "", err
	}
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		return "", "", fmt.Errorf("failed to derive public key: %w", err)
	}
	profile.PublicKey = pk

	// Update last used (and persist the backfilled pubkey). Best-effort:
	// failing to write profiles.json shouldn't block login.
	store.LastUsedProfile = id
	if err := SaveProfiles(store); err != nil {
		log.Printf("Warning: failed to save profiles: %v", err)
	}

	return sk, pk, nil
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

// defaultProfileID picks the profile the CLI should use when there is no
// legacy key file: the last-used profile, or the only profile if there is
// exactly one. Returns "" if there is no unambiguous choice.
func defaultProfileID() string {
	store, err := LoadProfiles()
	if err != nil || len(store.Profiles) == 0 {
		return ""
	}
	if _, ok := store.Profiles[store.LastUsedProfile]; ok {
		return store.LastUsedProfile
	}
	if len(store.Profiles) == 1 {
		for id := range store.Profiles {
			return id
		}
	}
	return ""
}

// profilePublicKey returns the stored hex pubkey of a profile, or "" if the
// profile doesn't exist or has none yet (migrated legacy profiles get theirs
// on first unlock).
func profilePublicKey(id string) string {
	store, err := LoadProfiles()
	if err != nil {
		return ""
	}
	if p, ok := store.Profiles[id]; ok {
		return p.PublicKey
	}
	return ""
}

// generateProfileID creates a unique profile ID. Uses crypto/rand.Read
// (returns an error if the system entropy source fails — vanishingly
// rare but possible). On error, fall back to a timestamp-derived ID
// rather than returning "0000000000000000" (the hex of an all-zero
// buffer), which would collide with every other failed call and
// silently overwrite profiles.json entries.
func generateProfileID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is extraordinary (kernel CSPRNG down).
		// Fall back to nanosecond timestamp; not cryptographic, but
		// distinct across calls within a single process and good
		// enough to prevent collision-induced data loss.
		return fmt.Sprintf("%x", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

// listPosts prints the user's 4 newest notes across all relays.
func listPosts(pubKey string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	events, failures := relay.QueryAll(ctx, getRelayList(), nostr.Filter{Authors: []string{pubKey}, Kinds: []int{1}, Limit: 4})
	for url, err := range failures {
		log.Printf("Error querying relay %s: %v", url, err)
	}
	if len(events) > 4 {
		events = events[:4]
	}
	fmt.Println("Last 4 posts from your profile:")
	for _, ev := range events {
		fmt.Printf("Created: %s\nContent: %s\n\n",
			time.Unix(int64(ev.CreatedAt), 0).Format(time.RFC1123), ev.Content)
	}
}

// feedLimit is how many posts the feed screen shows.
const feedLimit = 20

// eventToFeedPost converts a Nostr event to the TUI's display struct.
func eventToFeedPost(ev *nostr.Event) tui.FeedPost {
	return tui.FeedPost{
		Author:    ev.PubKey,
		Content:   ev.Content,
		CreatedAt: time.Unix(int64(ev.CreatedAt), 0).Format("Jan 2 15:04"),
	}
}

// newestFirst sorts events by created_at descending, de-duplicates by ID,
// and truncates to limit.
func newestFirst(events []*nostr.Event, limit int) []*nostr.Event {
	seen := make(map[string]bool, len(events))
	out := events[:0:0]
	for _, ev := range events {
		if ev == nil || seen[ev.ID] {
			continue
		}
		seen[ev.ID] = true
		out = append(out, ev)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].CreatedAt > out[j].CreatedAt })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// queryRelays queries every relay in parallel and returns the union of
// matching events (de-duplicated, newest first). Unreachable relays are
// skipped.
func queryRelays(ctx context.Context, relays []string, filters ...nostr.Filter) []*nostr.Event {
	events, _ := relay.QueryAll(ctx, relays, filters...)
	return events
}

// getFeedPosts returns the newest global kind-1 posts for TUI display.
//
// Relays are queried first; the local cache is only a fallback for when no
// relay answers. Previously cached events were inserted first and the loop
// stopped at 20 posts, so once the cache held 20 events the feed showed the
// same stale posts for the full 24h TTL and never displayed anything new.
func getFeedPosts() ([]tui.FeedPost, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	events := queryRelays(ctx, getRelayList(), nostr.Filter{Kinds: []int{1}, Limit: feedLimit})
	if eventCache != nil {
		for _, ev := range events {
			_ = eventCache.StoreEvent(ev, 24*time.Hour)
		}
		if len(events) == 0 {
			cached, _ := eventCache.GetEventsByPubKey("", 1, feedLimit)
			events = cached
		}
	}

	var posts []tui.FeedPost
	for _, ev := range newestFirst(events, feedLimit) {
		posts = append(posts, eventToFeedPost(ev))
	}
	return posts, nil
}

// dmLimit caps how many DMs are fetched and shown.
const dmLimit = 50

// dmFilters returns the two filters needed to see a user's whole NIP-04
// conversation history: messages they received (#p) and messages they sent
// (authors). The previous single filter {kinds:[4], limit:50} asked relays
// for the 50 newest DMs *on the whole network* and then discarded the ones
// that didn't involve the user — which in practice was nearly all of them.
func dmFilters(publicKey string) []nostr.Filter {
	return []nostr.Filter{
		{Kinds: []int{4}, Tags: nostr.TagMap{"p": []string{publicKey}}, Limit: dmLimit},
		{Kinds: []int{4}, Authors: []string{publicKey}, Limit: dmLimit},
	}
}

// decryptDM turns a kind-4 event into a display post if it involves the
// user. NIP-04's shared secret is ECDH(our privkey, *the other party's*
// pubkey): for an incoming DM that's the author, for an outgoing DM it's the
// p-tagged recipient. The old code always used the author, so the user's own
// sent messages could never be decrypted and silently vanished.
func decryptDM(ev *nostr.Event, privateKey, publicKey string) (tui.FeedPost, bool) {
	var recipient string
	if p := ev.Tags.GetFirst([]string{"p"}); p != nil && len(*p) > 1 {
		recipient = (*p)[1]
	}

	var counterparty, label string
	switch {
	case ev.PubKey == publicKey:
		if recipient == "" {
			return tui.FeedPost{}, false
		}
		counterparty = recipient
		label = "to " + shortKey(recipient)
	case recipient == publicKey:
		counterparty = ev.PubKey
		label = "from"
	default:
		return tui.FeedPost{}, false
	}

	ss, err := nip04.ComputeSharedSecret(counterparty, privateKey)
	if err != nil {
		return tui.FeedPost{}, false
	}
	plain, err := nip04.Decrypt(ev.Content, ss)
	if err != nil {
		return tui.FeedPost{}, false
	}
	return tui.FeedPost{
		Author:    ev.PubKey,
		Content:   fmt.Sprintf("[DM %s]: %s", label, plain),
		CreatedAt: time.Unix(int64(ev.CreatedAt), 0).Format("Jan 2 15:04"),
	}, true
}

// shortKey returns the first 8 chars of a key followed by "...", without
// panicking on short input.
func shortKey(k string) string {
	if len(k) > 8 {
		return k[:8] + "..."
	}
	return k
}

// getDMs returns the user's NIP-04 direct messages (sent and received),
// newest first.
func getDMs(privateKey string) ([]tui.FeedPost, error) {
	publicKey, err := nostr.GetPublicKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive public key: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	events := newestFirst(queryRelays(ctx, getRelayList(), dmFilters(publicKey)...), dmLimit)

	var dms []tui.FeedPost
	for _, ev := range events {
		if post, ok := decryptDM(ev, privateKey, publicKey); ok {
			dms = append(dms, post)
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
		Limit: 20,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var reactions []tui.FeedPost
	for _, ev := range newestFirst(queryRelays(ctx, relays, filter), 20) {
		content := ev.Content // reply
		if ev.Kind == 7 {
			content = fmt.Sprintf("[Reacted: %s]", ev.Content)
		}
		reactions = append(reactions, eventToFeedPost(ev))
		reactions[len(reactions)-1].Content = content
	}

	return reactions, nil
}

// publishPostTUI publishes a note using either NIP-46 or local key
func publishPostTUI(content string) error {
	var event nostr.Event
	var err error
	event.Kind = 1
	event.Content = content
	event.CreatedAt = nostr.Now()
	event.Tags = nostr.Tags{}

	// If NIP-46 session is active, use it
	if nip46Session != nil {
		event.PubKey = nip46Session.UserPublicKey
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := nip46Session.SignEvent(ctx, &event); err != nil {
			return fmt.Errorf("remote signing failed: %w", err)
		}
	} else {
		// Use local key
		if localPrivateKey == "" {
			return fmt.Errorf("no active session or local key")
		}
		event.PubKey, err = nostr.GetPublicKey(localPrivateKey)
		if err != nil {
			return fmt.Errorf("failed to get public key: %w", err)
		}
		if err := event.Sign(localPrivateKey); err != nil {
			return fmt.Errorf("failed to sign event: %w", err)
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _, err = relay.PublishAll(ctx, getRelayList(), event)
	return err
}

// getProfile prints the newest kind 0 (profile) event for pubKey.
func getProfile(pubKey string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	events, failures := relay.QueryAll(ctx, getRelayList(), nostr.Filter{Authors: []string{pubKey}, Kinds: []int{0}, Limit: 1})
	if len(events) == 0 {
		for url, err := range failures {
			log.Printf("Error querying relay %s: %v", url, err)
		}
		fmt.Println("Profile not found")
		return
	}
	fmt.Println("Your profile:")
	fmt.Println(events[0].Content)
}

// editProfile publishes a new kind 0 (profile) event with the updated profile info.
func editProfile(privateKey, newContent, pubKey string, relays []string) {
	event := nostr.Event{
		PubKey:    pubKey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      0,
		Content:   newContent,
		Tags:      nostr.Tags{},
	}
	if err := event.Sign(privateKey); err != nil {
		log.Fatalf("Failed to sign profile event: %v", err)
	}
	if err := publishAndReport(relays, event, "profile update"); err != nil {
		log.Printf("Profile update failed: %v", err)
	}
}

// publishAndReport publishes ev to relays in parallel and prints one line
// per relay. It returns an error only if no relay accepted the event.
func publishAndReport(relays []string, ev nostr.Event, what string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	accepted, failures, err := relay.PublishAll(ctx, relays, ev)
	for _, u := range accepted {
		fmt.Printf("Successfully published %s to relay: %s\n", what, u)
	}
	for u, ferr := range failures {
		fmt.Printf("Failed to publish to relay %s: %v\n", u, ferr)
	}
	if err != nil {
		return fmt.Errorf("%w (%d attempted)", err, len(failures))
	}
	if len(failures) > 0 {
		fmt.Printf("Published to %d relay(s); %d failed\n", len(accepted), len(failures))
	}
	return nil
}

// registerAsHandler registers the app as a handler for specific kinds.
func registerAsHandler(privateKey, publicKey string, kinds []int, platforms map[string]string) error {
	// Create a kind 31990 event for handler registration (NIP-89)
	event := nostr.Event{
		PubKey:    publicKey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      31990,
		Tags:      nostr.Tags{{"d", "hoot"}},
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

	return publishAndReport(getRelayList(), event, "handler registration")
}

// recommendApp publishes a recommendation for an app for a specific kind.
func recommendApp(privateKey, publicKey, handlerPubKey, handlerDIdentifier string, kind int, relayHint, platform string) error {
	// Create a kind 1985 event for app recommendation
	event := nostr.Event{
		PubKey:    publicKey,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1985,
		Tags: nostr.Tags{
			{"a", fmt.Sprintf("%d:%s:%s", kind, handlerPubKey, handlerDIdentifier)},
			{"p", platform},
		},
		Content: relayHint,
	}

	// Sign the event
	if err := event.Sign(privateKey); err != nil {
		return fmt.Errorf("failed to sign app recommendation event: %w", err)
	}

	return publishAndReport(getRelayList(), event, "app recommendation")
}

// findHandlers queries relays for NIP-89 handlers of a specific kind.
func findHandlers(kind int) ([]struct {
	PubKey         string
	SupportedKinds []int
	Platforms      map[string]string
}, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	events, _ := relay.QueryAll(ctx, getRelayList(), nostr.Filter{
		Kinds: []int{31990},
		Tags:  nostr.TagMap{"k": []string{fmt.Sprintf("%d", kind)}},
	})

	var handlers []struct {
		PubKey         string
		SupportedKinds []int
		Platforms      map[string]string
	}
	for _, ev := range events {
		handler := struct {
			PubKey         string
			SupportedKinds []int
			Platforms      map[string]string
		}{
			PubKey:    ev.PubKey,
			Platforms: make(map[string]string),
		}
		for _, tag := range ev.Tags {
			if len(tag) > 1 && tag[0] == "k" {
				if k, err := strconv.Atoi(tag[1]); err == nil {
					handler.SupportedKinds = append(handler.SupportedKinds, k)
				}
			} else if len(tag) > 2 && tag[0] == "p" {
				handler.Platforms[tag[1]] = tag[2]
			}
		}
		handlers = append(handlers, handler)
	}
	return handlers, nil
}

func main() {
	// Initialize cache for improved performance
	configDir := getConfigDir()
	var err error
	eventCache, err = cache.New(configDir)
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
	npubPtr := flag.Bool("npub", false, "Print your public key (npub) and exit")

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
		fmt.Printf("hoot %s (commit %s, built %s)\n", version, commit, date)
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
				sk, err := normalizePrivKey(privKey)
				if err != nil {
					return "", "", err
				}
				pk, err := nostr.GetPublicKey(sk)
				if err != nil {
					return "", "", err
				}
				// Cache for posting
				useLocalKey(sk)
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
				useLocalKey(sk)
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
				// Generate NIP-46 URI with ALL configured relays AND
				// a hard-coded set of relays Amber is known to publish
				// to (relay.damus.io, nostr.wine). The latter covers
				// the common failure mode where the user's relays.txt
				// is sparse or contains relays Amber doesn't recognise
				// — Amber then publishes to its own preferred relay
				// instead of the URI's, and hoot's subscription (only
				// on the user's relays) never sees the connect ack.
				//
				// See nip46.PairingRelays for the full rationale.
				userRelays := getRelayList()
				// Drop any previous session (and local key) first so a
				// retried scan doesn't leak relay connections.
				endRemoteSession()
				localPrivateKey = ""
				uri, session, err := nip46.GenerateConnectURI(nip46.PairingRelays(userRelays), "Hoot")
				if err != nil {
					return "", err
				}
				// Dial and subscribe in the background of this cmd.
				ctx := context.Background()
				if err := session.ConnectRelays(ctx); err != nil {
					return "", fmt.Errorf("relay connect: %w", err)
				}
				nip46Session = session
				return uri, nil
			},
			OnCheckQR: func() (string, *nip46.ProfileMetadata, error) {
				if nip46Session == nil {
					return "", nil, fmt.Errorf("session not initialized")
				}
				// Short poll — the subscriptions are already active
				// from ConnectRelays called in OnInitQR. We just
				// check if the signer's connect event arrived yet.
				pubKey, err := nip46Session.CheckConnection(3 * time.Second)
				if err != nil {
					return "", nil, err // TUI will retry
				}

				// Got connect — now request the user's public key.
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				userPubKey, err := nip46Session.GetPublicKey(ctx)
				if err != nil {
					return pubKey, nil, nil // fall back to signer pubkey
				}

				// Fetch the user's kind-0 profile metadata so the
				// home screen can render their name + about + nip-05
				// instead of just a 16-char pubkey prefix. Failure
				// here is non-fatal: many users have no profile, and
				// the caller falls back to the npub display.
				profileCtx, profileCancel := context.WithTimeout(context.Background(), 6*time.Second)
				defer profileCancel()
				profile, _ := nip46Session.FetchProfile(profileCtx, userPubKey)
				if profile != nil && eventCache != nil {
					// Cache the freshly-fetched profile so subsequent
					// logins can render the name immediately without
					// hitting the relays again. 24h TTL matches the
					// profile event re-publish cadence most signers
					// use (kind 0 is replaceable).
					_ = eventCache.StoreProfile(
						profile.PubKey,
						profile.Name,
						profile.About,
						profile.Picture,
						profile.NIP05,
						time.Now().Unix(),
						24*time.Hour,
					)
				}
				return userPubKey, profile, nil
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
				useLocalKey(privKey)
				return privKey, pubKey, nil
			},
			OnAddProfile: func(name, nsec, password string) (string, string, error) {
				profile, err := AddProfile(name, nsec, password)
				if err != nil {
					return "", "", err
				}
				sk, err := normalizePrivKey(nsec)
				if err != nil {
					return "", "", err
				}
				// Cache the private key for posting
				useLocalKey(sk)
				return sk, profile.PublicKey, nil
			},
			OnDeleteProfile: DeleteProfile,
			OnTip: func(target string, sats int64) (string, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				res, err := tipUser(ctx, target, sats, nil)
				if err != nil {
					return "", err
				}
				return res.String(), nil
			},
			OnLogout: func() {
				endRemoteSession()
				localPrivateKey = ""
			},
		}
		if err := tui.Run(cfg); err != nil {
			log.Fatalf("TUI error: %v", err)
		}
		return
	}

	// Handle NWC setup
	if *nwcPtr != "" {
		if err := saveNWCURI(*nwcPtr); err != nil {
			log.Fatalf("Failed to save NWC URI: %v", err)
		}
		fmt.Println("NWC URI saved successfully.")
		return
	}

	// Handle Tipping
	if *tipPtr > 0 {
		if *tipUserPtr == "" {
			log.Fatalf("Please specify who to tip with -user (lightning address, npub or hex pubkey)")
		}
		res, err := tipUser(context.Background(), *tipUserPtr, *tipPtr, func(s string) { fmt.Println(s) })
		if err != nil {
			log.Fatalf("Tip failed: %v", err)
		}
		fmt.Println(res.String())
		if res.Preimage != "" {
			fmt.Printf("Preimage: %s\n", res.Preimage)
		}
		return
	}

	// Check if key exists. Profiles created in the TUI count too —
	// previously the CLI only knew about the legacy nostr_key.enc, so
	// anyone who set up hoot through the TUI was told "No private key
	// found" by every CLI command.
	keyPath := filepath.Join(configDir, keyFileName)
	_, err = os.Stat(keyPath)
	keyExists := !os.IsNotExist(err)
	cliProfileID := ""
	if !keyExists {
		cliProfileID = defaultProfileID()
		keyExists = cliProfileID != ""
	}

	// -npub: profiles store the public key in the clear, so no password
	// is needed for them. A legacy key file only has the encrypted private
	// key, so that case falls through to the normal unlock below.
	if *npubPtr {
		if !keyExists {
			log.Fatalf("No key stored: add a profile in the TUI, or run: hoot -s -k <nsec>")
		}
		if cliProfileID != "" {
			if pk := profilePublicKey(cliProfileID); pk != "" {
				npub, err := nip19.EncodePublicKey(pk)
				if err != nil {
					log.Fatalf("Invalid stored public key: %v", err)
				}
				fmt.Println(npub)
				return
			}
		}
	}

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

	// Read encryption password without echoing
	// Check for password in environment variable first (for testing/automation)
	password := os.Getenv("HOOT_PASSWORD")
	if password == "" {
		// Read encryption password without echoing
		// Prompts and progress go to stderr so stdout stays clean for
		// scripts, e.g. NPUB=$(hoot -npub).
		fmt.Fprint(os.Stderr, "Enter encryption password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatalf("Error reading password: %v", err)
		}
		fmt.Fprintln(os.Stderr) // newline after password input
		password = string(bytePassword)
	}

	// Save a new key action with loading bar.
	if *storePtr {
		if *keyPtr == "" {
			fmt.Println("Error: Must provide a private key with -k when using -s")
			os.Exit(1)
		}
		err := withLoading("Storing key", func() error {
			return saveKey(*keyPtr, []byte(password))
		})
		if err != nil {
			log.Fatalf("Failed to store key: %v", err)
		}
		return
	}

	var privateKey string
	if err := withLoading("Loading key", func() error {
		var err error
		if cliProfileID != "" {
			privateKey, _, err = UnlockProfile(cliProfileID, password)
		} else {
			privateKey, err = loadKey([]byte(password))
		}
		return err
	}); err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	// For actions that need the private key decoded and public key derived,
	// decode it appropriately.
	sk, err := normalizePrivKey(privateKey)
	if err != nil {
		log.Fatalf("Invalid stored key: %v", err)
	}
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		log.Fatalf("Failed to derive public key: %v", err)
	}

	if *npubPtr {
		npub, _ := nip19.EncodePublicKey(pk)
		fmt.Println(npub)
		return
	}

	// Handle NIP-89 register-handler command
	if *registerHandlerPtr != "" {
		kindStrs := strings.Split(*registerHandlerPtr, ",")
		var kinds []int
		for _, kindStr := range kindStrs {
			kind, err := strconv.Atoi(strings.TrimSpace(kindStr))
			if err != nil {
				log.Fatalf("Invalid kind: %s", kindStr)
			}
			kinds = append(kinds, kind)
		}

		if *urlTemplatePtr == "" {
			log.Fatalf("URL template is required for handler registration")
		}

		platforms := map[string]string{
			*platformPtr: *urlTemplatePtr,
		}

		err := withLoading("Registering handler", func() error {
			return registerAsHandler(sk, pk, kinds, platforms)
		})
		if err != nil {
			log.Fatalf("Failed to register handler: %v", err)
		}
		return
	}

	// Handle NIP-89 recommend command
	if *recommendPtr != "" {
		parts := strings.Split(*recommendPtr, ":")
		if len(parts) != 3 {
			log.Fatalf("Invalid recommend format. Use: pubkey:d-identifier:kind")
		}

		handlerPubKey := parts[0]
		handlerDIdentifier := parts[1]
		kind, err := strconv.Atoi(parts[2])
		if err != nil {
			log.Fatalf("Invalid kind: %s", parts[2])
		}

		relayHint := ""
		if *relaysPtr != "" {
			relays := strings.Split(*relaysPtr, ",")
			relayHint = strings.TrimSpace(relays[0])
		} else {
			relayList := getRelayList()
			if len(relayList) > 0 {
				relayHint = relayList[0]
			}
		}

		err = withLoading("Publishing recommendation", func() error {
			return recommendApp(sk, pk, handlerPubKey, handlerDIdentifier, kind, relayHint, *platformPtr)
		})
		if err != nil {
			log.Fatalf("Failed to publish recommendation: %v", err)
		}
		return
	}

	// Handle NIP-89 find-handlers command
	if *findHandlersPtr > 0 {
		err := withLoading("Finding handlers", func() error {
			handlers, err := findHandlers(*findHandlersPtr)
			if err != nil {
				return err
			}

			if len(handlers) == 0 {
				fmt.Printf("No handlers found for kind %d\n", *findHandlersPtr)
				return nil
			}

			fmt.Printf("Found %d handlers for kind %d:\n", len(handlers), *findHandlersPtr)
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
		if err != nil {
			log.Fatalf("Failed to find handlers: %v", err)
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
		_ = withLoading("Retrieving profile", func() error {
			getProfile(pk)
			return nil
		})
		return
	}

	// Handle list posts action with loading.
	if *listPtr {
		_ = withLoading("Listing posts", func() error {
			listPosts(pk)
			return nil
		})
		return
	}

	// Handle DMs action with loading.
	if *dmsPtr {
		err = withLoading("Loading DMs", func() error {
			dms, err := getDMs(sk)
			if err != nil {
				return fmt.Errorf("failed to load DMs: %w", err)
			}
			fmt.Println("Your recent direct messages:")
			for _, dm := range dms {
				fmt.Printf("%s (%s): %s\n\n", shortKey(dm.Author), dm.CreatedAt, dm.Content)
			}
			return nil
		})
		if err != nil {
			log.Fatalf("Failed to load DMs: %v", err)
		}
		return
	}

	// Handle replies action with loading.
	if *repliesPtr != "" {
		err = withLoading("Loading replies", func() error {
			replies, err := getReactions(*repliesPtr)
			if err != nil {
				return fmt.Errorf("failed to load replies: %w", err)
			}
			fmt.Printf("Replies and reactions to event %s:\n", *repliesPtr)
			for _, reply := range replies {
				fmt.Printf("%s (%s): %s\n\n", shortKey(reply.Author), reply.CreatedAt, reply.Content)
			}
			return nil
		})
		if err != nil {
			log.Fatalf("Failed to load replies: %v", err)
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
		_ = withLoading("Retrieving profile", func() error {
			getProfile(pk)
			return nil
		})
		return
	}

	// Handle profile update action with loading.
	if *updatePtr != "" {
		var relays []string
		if *relaysPtr != "" {
			relays = strings.Split(*relaysPtr, ",")
			for i := range relays {
				relays[i] = strings.TrimSpace(relays[i])
			}
		} else {
			relays = getRelayList()
		}
		_ = withLoading("Updating profile", func() error {
			editProfile(sk, *updatePtr, pk, relays)
			return nil
		})
		return
	}

	// Prepare a new post event.
	event := nostr.Event{
		PubKey:    pk,
		CreatedAt: nostr.Timestamp(time.Now().Unix()),
		Kind:      1,
		Content:   *messagePtr,
		Tags:      nostr.Tags{},
	}
	words := strings.Fields(event.Content)
	for _, word := range words {
		if strings.HasPrefix(word, "#") {
			tag := strings.Trim(word, "#.,!?:;")
			event.Tags = append(event.Tags, []string{"t", tag})
		}
	}
	if err = event.Sign(sk); err != nil {
		log.Fatalf("Failed to sign event: %v", err)
	}

	// Prepare relays.
	var relays []string
	if *relaysPtr != "" {
		relays = strings.Split(*relaysPtr, ",")
		for i := range relays {
			relays[i] = strings.TrimSpace(relays[i])
		}
	} else {
		relays = getRelayList()
	}

	// Publish the event using a relay pool with a loading bar.
	// On error (no relay accepted the event), fall through to log + exit
	// non-zero instead of log.Fatalf, so defers (eventCache.Close, etc.)
	// actually run — the prior code skipped them with os.Exit.
	if err := withLoading("Publishing post", func() error {
		return publishNote(context.Background(), relays, event)
	}); err != nil {
		log.Printf("Publishing failed: %v", err)
		os.Exit(1)
	}
}

// publishNote publishes a signed event to all relays in parallel, printing
// a line per relay, and returns an error if no relay accepted it.
func publishNote(ctx context.Context, relays []string, event nostr.Event) error {
	_ = ctx // publishAndReport applies its own timeout
	return publishAndReport(relays, event, "note")
}
