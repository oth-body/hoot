package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
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
)

const (
	appName     = "nostr-cli"
	keyFileName = "nostr_key.enc"
	version     = "0.0.4" // Define the version here
)

var defaultRelays = []string{
	"wss://relay.damus.io",
	"wss://relay.nostr.band",
	"wss://nostr.wine",
	"wss://nostr.wine",
}

// Global NIP-46 session and local key
var nip46Session *nip46.Session
var localPrivateKey string

// Updated StoredKey includes the password hash.
type StoredKey struct {
	EncryptedKey []byte `json:"encrypted_key"`
	Salt         []byte `json:"salt"`
	// PasswordHash stores the bcrypt hash of the password.
	PasswordHash string `json:"password_hash"`
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
				time.Sleep(100 * time.Millisecond)
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

// listPosts queries posts (kind 1 events) and prints the last 4 posts.
func listPosts(pubKey string) {
	// Use relay list from file or default.
	relays := getRelayList()
	filter := nostr.Filter{
		Authors: []string{pubKey},
		Kinds:   []int{1},
		Limit:   4,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
	fmt.Println("Last 4 posts from your profile:")
	for _, ev := range events {
		fmt.Printf("Created: %s\nContent: %s\n\n",
			time.Unix(int64(ev.CreatedAt), 0).Format(time.RFC1123), ev.Content)
	}
}

// getFeedPosts returns posts from the global feed for TUI display
func getFeedPosts() ([]tui.FeedPost, error) {
	relays := getRelayList()
	filter := nostr.Filter{
		Kinds: []int{1},
		Limit: 20,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var posts []tui.FeedPost
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
			posts = append(posts, tui.FeedPost{
				Author:    ev.PubKey,
				Content:   ev.Content,
				CreatedAt: time.Unix(int64(ev.CreatedAt), 0).Format("Jan 2 15:04"),
			})
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

// publishPostTUI publishes a note using either NIP-46 or local key
func publishPostTUI(content string) error {
	var event nostr.Event
	event.Kind = 1
	event.Content = content
	event.CreatedAt = nostr.Now()
	event.Tags = nostr.Tags{}

	relays := getRelayList()

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
		event.PubKey, _ = nostr.GetPublicKey(localPrivateKey)
		event.Sign(localPrivateKey)
	}

	success := 0
	for _, url := range relays {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		relay, err := nostr.RelayConnect(ctx, url)
		if err != nil {
			continue
		}
		if err := relay.Publish(ctx, event); err == nil {
			success++
		}
		relay.Close()
	}

	if success == 0 {
		return fmt.Errorf("failed to publish to any relay")
	}
	return nil
}

// getProfile queries for a kind 0 (profile) event.
func getProfile(pubKey string) {
	// Use relay list from file or default.
	relays := getRelayList()
	filter := nostr.Filter{
		Authors: []string{pubKey},
		Kinds:   []int{0},
		Limit:   1,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
			profileEvent = ev
			break
		}
		relay.Close()
		if profileEvent != nil {
			break
		}
	}
	if profileEvent == nil {
		fmt.Println("Profile not found")
		return
	}
	fmt.Println("Your profile:")
	fmt.Println(profileEvent.Content)
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
		defer relay.Close()

		if err := relay.Publish(ctx, event); err != nil {
			log.Printf("Failed to publish to relay %s: %v", relay.URL, err)
		} else {
			fmt.Printf("Handler registration published to relay: %s\n", relay.URL)
		}
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
		defer relay.Close()

		if err := relay.Publish(ctx, event); err != nil {
			log.Printf("Failed to publish to relay %s: %v", relay.URL, err)
		} else {
			fmt.Printf("App recommendation published to relay: %s\n", relay.URL)
		}
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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
		defer relay.Close()

		evCh, err := relay.QueryEvents(ctx, filter)
		if err != nil {
			log.Printf("Error querying relay %s: %v", url, err)
			continue
		}

		for ev := range evCh {
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
	}
	return handlers, nil
}

func payInvoiceNWC(invoice string) error {
	// 1. Get NWC URI
	uriStr, err := getNWCURI()
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

func saveNWCURI(uri string) error {
	configDir := getConfigDir()
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}
	path := filepath.Join(configDir, "nwc.txt")
	return os.WriteFile(path, []byte(uri), 0600)
}

func getNWCURI() (string, error) {
	configDir := getConfigDir()
	path := filepath.Join(configDir, "nwc.txt")
	data, err := os.ReadFile(path)
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
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

func main() {
	// Define command-line flags
	messagePtr := flag.String("m", "", "Message to post (optional)")
	keyPtr := flag.String("k", "", "Private key to store (use with -s)")
	storePtr := flag.Bool("s", false, "Store a new private key")
	relaysPtr := flag.String("r", "", "Comma-separated list of relay URLs")
	listPtr := flag.Bool("l", false, "List last 4 posts from your profile")
	profilePtr := flag.Bool("p", false, "Retrieve and display profile info")
	updatePtr := flag.String("u", "", "Update profile info")
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
				localPrivateKey = sk
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
				localPrivateKey = sk
				return pk, nil
			},
			OnPost:     publishPostTUI,
			OnLoadFeed: getFeedPosts,
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
				nip46Session = session
				return uri, nil
			},
			OnCheckQR: func() (string, error) {
				if nip46Session == nil {
					return "", fmt.Errorf("session not initialized")
				}
				// Wait for connection
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()

				if err := nip46Session.WaitForConnection(ctx); err != nil {
					return "", err
				}

				// Get public key
				pubKey, err := nip46Session.GetPublicKey(ctx)
				if err != nil {
					return "", err
				}

				return pubKey, nil
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
			log.Fatalf("Please specify a user to tip with -user")
		}

		target := *tipUserPtr
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
					log.Fatalf("Invalid npub: %v", err)
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
				log.Fatalf("Could not find lightning address for user: %v", err)
			}
			lud16 = l
		}

		fmt.Printf("Found lightning address: %s\n", lud16)

		// Resolve Callback
		callback, err := resolveLud16(lud16)
		if err != nil {
			log.Fatalf("Failed to resolve lightning address: %v", err)
		}

		// Fetch Invoice
		fmt.Printf("Fetching invoice for %d sats...\n", *tipPtr)
		invoice, err := fetchLightningInvoice(callback, *tipPtr)
		if err != nil {
			log.Fatalf("Failed to fetch invoice: %v", err)
		}

		// Pay
		fmt.Println("Paying invoice via NWC...")
		if err := payInvoiceNWC(invoice); err != nil {
			log.Fatalf("Payment failed: %v", err)
		}
		return
	}

	// Check if key exists
	configDir := getConfigDir()
	keyPath := filepath.Join(configDir, keyFileName)
	_, err := os.Stat(keyPath)
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

	// Read encryption password without echoing
	// Check for password in environment variable first (for testing/automation)
	password := os.Getenv("HOOT_PASSWORD")
	if password == "" {
		// Read encryption password without echoing
		fmt.Print("Enter encryption password: ")
		bytePassword, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			log.Fatalf("Error reading password: %v", err)
		}
		fmt.Println("") // newline after password input
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
		privateKey, err = loadKey([]byte(password))
		return err
	}); err != nil {
		log.Fatalf("Failed to load private key: %v", err)
	}

	// For actions that need the private key decoded and public key derived,
	// decode it appropriately.
	var sk string
	if strings.HasPrefix(privateKey, "nsec") {
		_, decoded, err := nip19.Decode(privateKey)
		if err != nil {
			log.Fatalf("Invalid nsec key: %v", err)
		}
		sk = decoded.(string)
	} else {
		sk = privateKey
	}
	pk, err := nostr.GetPublicKey(sk)
	if err != nil {
		log.Fatalf("Failed to derive public key: %v", err)
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
	err = withLoading("Publishing post", func() error {
		ctx := context.Background()
		pool := nostr.NewSimplePool(ctx)
		for _, relayURL := range relays {
			relay, err := pool.EnsureRelay(relayURL)
			if err != nil {
				log.Printf("Failed to add relay %s: %v", relayURL, err)
				continue
			}
			defer relay.Close()
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
	if err != nil {
		log.Fatalf("Publishing failed: %v", err)
	}
}
