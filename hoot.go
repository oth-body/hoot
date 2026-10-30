package main

import (
	"context"
	"flag"
	"fmt"
	"hoot/cache"
	"hoot/tui"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"golang.org/x/term"
)

// version, commit, and date are set at build time by goreleaser via
// ldflags: -X main.version=... -X main.commit=... -X main.date=...
// When built with plain `go build`, they keep their defaults.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// Global cache instance for improved performance
var eventCache *cache.Cache

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
	dmToPtr := flag.String("dm", "", "Send the -m message as a private DM (NIP-17) to this npub or hex pubkey")
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

		cfg := tuiConfig()
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
			useLocalKey(sk)
			dms, err := getDMs()
			if err != nil {
				return fmt.Errorf("failed to load DMs: %w", err)
			}
			fmt.Println("Your recent direct messages:")
			for _, dm := range dms {
				fmt.Printf("%s (%s): %s\n\n", postAuthor(dm), dm.CreatedAt, dm.Content)
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
				fmt.Printf("%s (%s): %s\n\n", postAuthor(reply), reply.CreatedAt, reply.Content)
			}
			return nil
		})
		if err != nil {
			log.Fatalf("Failed to load replies: %v", err)
		}
		return
	}

	// If no message is provided, just show the public key and exit.
	if *dmToPtr != "" && *messagePtr == "" {
		log.Fatalf("Use -dm together with -m \"message\"")
	}
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

	// Send a private DM instead of a public note.
	if *dmToPtr != "" {
		to, err := parsePubKey(strings.TrimSpace(*dmToPtr))
		if err != nil {
			log.Fatalf("Invalid -dm recipient: %v", err)
		}
		useLocalKey(sk)
		if err := withLoading("Sending DM", func() error { return sendDM(to, *messagePtr) }); err != nil {
			log.Printf("Sending DM failed: %v", err)
			os.Exit(1)
		}
		fmt.Println("DM sent.")
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
	event.Tags = append(event.Tags, hashtagTags(event.Content)...)
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
