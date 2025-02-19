package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/term"
)

const (
	appName     = "nostr-cli"
	keyFileName = "nostr_key.enc"
)

var defaultRelays = []string{
	"wss://relay.damus.io",
	"wss://relay.nostr.band",
	"wss://nostr.wine",
}

// Updated StoredKey includes the password hash.
type StoredKey struct {
	EncryptedKey []byte `json:"encrypted_key"`
	Salt         []byte `json:"salt"`
	// PasswordHash stores the bcrypt hash of the password.
	PasswordHash string `json:"password_hash"`
}

// withLoading shows a simple spinner until fn() finishes.
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
	if err := checkPassword(storedKey.PasswordHash, string(password)); err != nil {
		return nil, fmt.Errorf("password verification failed: %w", err)
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

func main() {
	// Define command-line flags
	messagePtr := flag.String("m", "", "Message to post (optional)")
	keyPtr := flag.String("k", "", "Private key to store (use with -s)")
	storePtr := flag.Bool("s", false, "Store a new private key")
	relaysPtr := flag.String("r", "", "Comma-separated list of relay URLs")
	listPtr := flag.Bool("l", false, "List last 4 posts from your profile")
	profilePtr := flag.Bool("p", false, "Retrieve and display profile info")
	updatePtr := flag.String("u", "", "Update profile info")
	flag.Parse()

	// Read encryption password without echoing
	fmt.Print("Enter encryption password: ")
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		log.Fatalf("Error reading password: %v", err)
	}
	fmt.Println("") // newline after password input
	password := string(bytePassword)

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

	// *** Show the list of relays loaded from file (or defaults) ***
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
