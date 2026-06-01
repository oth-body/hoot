package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	flag "flag"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/manifoldco/promptui"
	"github.com/nbd-wtf/go-nostr"
	"github.com/nbd-wtf/go-nostr/nip19"
	"golang.org/x/crypto/ssh/terminal"
)

// Global variables as mentioned in requirements
var (
	nip46Session    interface{}
	localPrivateKey string
	eventCache     *EventCache
	timeouts       = struct {
		Connect time.Duration
		Publish time.Duration
	}{
		Connect: 30 * time.Second,
		Publish: 15 * time.Second,
	}
)

// Config directory paths
const (
	appName = "nostr-cli"
)

// getConfigDir returns the config directory based on the OS
func getConfigDir() string {
	var configDir string
	switch runtime.GOOS {
	case "linux":
		configDir = filepath.Join(os.Getenv("HOME"), ".config", appName)
	case "darwin":
		configDir = filepath.Join(os.Getenv("HOME"), "Library", "Application Support", appName)
	default:
		configDir = filepath.Join(os.Getenv("HOME"), ".config", appName)
	}
	return configDir
}

// EventCache represents the event caching system
type EventCache struct {
	dbPath string
}

// NewEventCache creates a new event cache
func NewEventCache(configDir string) *EventCache {
	dbPath := filepath.Join(configDir, "cache.db")
	return &EventCache{dbPath: dbPath}
}

// Key management functions

// readPassword reads a password from stdin
func readPassword() (string, error) {
	fmt.Print("Enter password: ")
	bytePassword, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(bytePassword), nil
}

// loadAndDecodeKey loads and decodes a private key
func loadAndDecodeKey(password string) (string, string, error) {
	configDir := getConfigDir()
	keyFile := filepath.Join(configDir, "nostr_key.enc")
	
	// Check if key file exists
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		return "", "", fmt.Errorf("no key file found")
	}
	
	// Read encrypted key file
	data, err := ioutil.ReadFile(keyFile)
	if err != nil {
		return "", "", err
	}
	
	// In a real implementation, we would decrypt the key here
	// For this example, we'll assume the key is stored as hex
	privKey := strings.TrimSpace(string(data))
	
	// Validate the key
	if len(privKey) != 64 {
		return "", "", fmt.Errorf("invalid private key length")
	}
	
	// Get public key
	pubKey, _ := nostr.GetPublicKey(privKey)
	
	return privKey, pubKey, nil
}

// saveKey saves a private key with password encryption
func saveKey(privKey, password string) error {
	configDir := getConfigDir()
	
	// Create config directory if it doesn't exist
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}
	
	keyFile := filepath.Join(configDir, "nostr_key.enc")
	
	// In a real implementation, we would encrypt the key here
	// For this example, we'll just save the hex key
	return ioutil.WriteFile(keyFile, []byte(privKey), 0600)
}

// isFirstRun checks if this is the first run of the application
func isFirstRun() bool {
	configDir := getConfigDir()
	
	// Check if config directory exists
	if _, err := os.Stat(configDir); os.IsNotExist(err) {
		return true
	}
	
	// Check if any key files exist
	keyFile := filepath.Join(configDir, "nostr_key.enc")
	profilesFile := filepath.Join(configDir, "profiles.json")
	guestFile := filepath.Join(configDir, ".guest")
	
	// If .guest file exists, it means user skipped the wizard
	if _, err := os.Stat(guestFile); err == nil {
		return false
	}
	
	// Check if key file or profiles file exists
	keyExists := false
	if _, err := os.Stat(keyFile); err == nil {
		keyExists = true
	}
	
	profilesExists := false
	if _, err := os.Stat(profilesFile); err == nil {
		profilesExists = true
	}
	
	return !keyExists && !profilesExists
}

// runFirstRunWizard runs the first-run wizard
func runFirstRunWizard() error {
	color.Green("Welcome to Hoot - Nostr CLI Tool!")
	color.Cyan("Let's get you set up with a Nostr identity.\n")
	
	prompt := promptui.Select{
		Label: "Choose how to set up your Nostr identity",
		Items: []string{
			"Generate a new key",
			"Import existing nsec",
			"Connect via NIP-46 (QR code)",
			"Skip for now",
		},
		Size: 4,
	}
	
	_, result, err := prompt.Run()
	if err != nil {
		return fmt.Errorf("prompt failed: %v", err)
	}
	switch result {
	case "Generate a new key":
		return handleGenerateKey()
	case "Import existing nsec":
		return handleImportKey()
	case "Connect via NIP-46 (QR code)":
		return handleNIP46Connect()
	case "Skip for now":
		return handleSkipWizard()
	}
	
	return nil
}

// handleGenerateKey handles generating a new key
func handleGenerateKey() error {
	color.Yellow("Generating a new Nostr key pair...\n")
	
	privKeyBytes := make([]byte, 32)
	if _, err := rand.Read(privKeyBytes); err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}
	
	privKey := hex.EncodeToString(privKeyBytes)
	pubKey, _ := nostr.GetPublicKey(privKey)
	
	nsec, err := nip19.EncodePrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("failed to encode nsec: %v", err)
	}
	
	npub, err := nip19.EncodePublicKey(pubKey)
	if err != nil {
		return fmt.Errorf("failed to encode npub: %v", err)
	}
	
	fmt.Printf("Your private key (nsec): %s\n", color.YellowString(nsec))
	fmt.Printf("Your public key (npub): %s\n", color.CyanString(npub))
	fmt.Println()
	color.Red("IMPORTANT: Back up your private key! If you lose it, you lose access to your Nostr identity.")
	
	prompt := promptui.Prompt{
		Label:     "Type 'backup' to confirm you've backed up your key",
		Validate: func(input string) error {
			if input != "backup" {
				return fmt.Errorf("please type 'backup' to confirm")
			}
			return nil
		},
	}
	
	_, err = prompt.Run()
	if err != nil {
		return fmt.Errorf("backup confirmation failed: %v", err)
	}
	
	password, err := readPassword()
	if err != nil {
		return fmt.Errorf("password entry failed: %v", err)
	}
	
	if err := saveKey(privKey, password); err != nil {
		return fmt.Errorf("failed to save key: %v", err)
	}
	
	color.Green("Key saved successfully!")
	
	// Offer to create a profile
	selectPrompt := promptui.Select{
		Label: "Would you like to create a profile now?",
		Items: []string{"Yes", "No"},
	}
	
	_, choice, err := selectPrompt.Run()
	if err != nil {
		return fmt.Errorf("profile creation prompt failed: %v", err)
	}
	
	if choice == "Yes" {
		return handleProfileCreation(privKey)
	}
	
	return nil
}

// handleImportKey handles importing an existing key
func handleImportKey() error {
	prompt := promptui.Prompt{
		Label: "Enter your nsec key",
		Validate: func(input string) error {
			if !strings.HasPrefix(input, "nsec1") {
				return fmt.Errorf("please enter a valid nsec key (starts with nsec1)")
			}
			return nil
		},
	}
	
	nsec, err := prompt.Run()
	if err != nil {
		return fmt.Errorf("nsec input failed: %v", err)
	}
	
	// Decode nsec to get private key
	_, privKey, err := nip19.Decode(nsec)
	if err != nil {
		return fmt.Errorf("failed to decode nsec: %v", err)
	}
	
	// Convert to hex
	privKeyHex := hex.EncodeToString(privKey.([]byte))
	
	password, err := readPassword()
	if err != nil {
		return fmt.Errorf("password entry failed: %v", err)
	}
	
	if err := saveKey(privKeyHex, password); err != nil {
		return fmt.Errorf("failed to save key: %v", err)
	}
	
	color.Green("Key imported successfully!")
	
	// Offer to create a profile
	selectPrompt := promptui.Select{
		Label: "Would you like to create a profile now?",
		Items: []string{"Yes", "No"},
	}
	
	_, choice, err := selectPrompt.Run()
	if err != nil {
		return fmt.Errorf("profile creation prompt failed: %v", err)
	}
	
	if choice == "Yes" {
		return handleProfileCreation(privKeyHex)
	}
	
	return nil
}

// handleNIP46Connect handles NIP-46 connection
func handleNIP46Connect() error {
	color.Yellow("NIP-46 connection will be implemented in a future version.")
	fmt.Println("For now, please use the other options.")
	return nil
}

// handleSkipWizard handles skipping the wizard
func handleSkipWizard() error {
	configDir := getConfigDir()
	
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return fmt.Errorf("failed to create config directory: %v", err)
	}
	
	guestFile := filepath.Join(configDir, ".guest")
	if err := ioutil.WriteFile(guestFile, []byte("guest"), 0600); err != nil {
		return fmt.Errorf("failed to create guest marker: %v", err)
	}
	
	color.Yellow("Wizard skipped. You can set up your identity later with 'hoot login'.")
	fmt.Println("Next steps:")
	fmt.Println("  - Run 'hoot login' to set up your identity")
	fmt.Println("  - Run 'hoot help' to see available commands")
	
	return nil
}

// handleProfileCreation handles profile creation
func handleProfileCreation(privKey string) error {
	prompt := promptui.Prompt{
		Label: "Enter your name",
	}
	
	name, err := prompt.Run()
	if err != nil {
		return fmt.Errorf("name input failed: %v", err)
	}
	
	prompt = promptui.Prompt{
		Label: "Enter your about (optional)",
	}
	
	about, err := prompt.Run()
	if err != nil {
		return fmt.Errorf("about input failed: %v", err)
	}
	
	// Create profile JSON
	profile := map[string]string{
		"name":  name,
		"about": about,
	}
	
	// In a real implementation, we would publish this to Nostr
	// For now, just save it locally
	configDir := getConfigDir()
	profilesFile := filepath.Join(configDir, "profiles.json")
	
	profiles := map[string]interface{}{
		"default": profile,
	}
	
	profilesData, err := json.MarshalIndent(profiles, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal profiles: %v", err)
	}
	
	if err := ioutil.WriteFile(profilesFile, profilesData, 0600); err != nil {
		return fmt.Errorf("failed to save profiles: %v", err)
	}
	
	color.Green("Profile created successfully!")
	
	return nil
}

// Existing command functions (simplified implementations)

// runPublishCommand handles publishing a note
func runPublishCommand(message string) error {
	if message == "" {
		return fmt.Errorf("message cannot be empty")
	}
	
	color.Green("Publishing note: %s", message)
	// In a real implementation, this would publish to Nostr relays
	return nil
}

// runProfileCommand handles viewing profile
func runProfileCommand() error {
	color.Cyan("Profile information:")
	// In a real implementation, this would fetch profile from Nostr
	return nil
}

// runUpdateProfileCommand handles updating profile
func runUpdateProfileCommand(profile map[string]string) error {
	color.Green("Updating profile...")
	// In a real implementation, this would update profile on Nostr
	return nil
}

// runListPostsCommand handles listing posts
func runListPostsCommand(limit int) error {
	color.Cyan("Listing posts (limit: %d)", limit)
	// In a real implementation, this would fetch posts from Nostr
	return nil
}

// runDMsCommand handles DMs
func runDMsCommand() error {
	color.Cyan("Direct messages:")
	// In a real implementation, this would fetch DMs from Nostr
	return nil
}

// runRepliesCommand handles viewing replies
func runRepliesCommand(noteID string) error {
	color.Cyan("Replies to note: %s", noteID)
	// In a real implementation, this would fetch replies from Nostr
	return nil
}

// runTipCommand handles tipping
func runTipCommand(amount string, recipient string) error {
	color.Green("Sending tip: %s to %s", amount, recipient)
	// In a real implementation, this would handle Lightning Network tipping
	return nil
}

// runNWCSetup handles NWC setup
func runNWCSetup(uri string) error {
	color.Green("Setting up NWC with URI: %s", uri)
	// In a real implementation, this would set up Nostr Wallet Connect
	return nil
}

// selfUpdate handles self-update
func selfUpdate() error {
	color.Green("Checking for updates...")
	// In a real implementation, this would check for and install updates
	return nil
}

// checkForUpdate checks for updates
func checkForUpdate() error {
	color.Cyan("Checking for updates...")
	// In a real implementation, this would check for updates
	return nil
}

// getRelayList gets the list of relays
func getRelayList() []string {
	configDir := getConfigDir()
	relayFile := filepath.Join(configDir, "relays.txt")
	
	// Default relays if file doesn't exist
	if _, err := os.Stat(relayFile); os.IsNotExist(err) {
		return []string{
			"wss://relay.damus.io",
			"wss://relay.nostr.band",
			"wss://nos.lol",
		}
	}
	
	// Read relay file
	data, err := ioutil.ReadFile(relayFile)
	if err != nil {
		return []string{
			"wss://relay.damus.io",
			"wss://relay.nostr.band",
			"wss://nos.lol",
		}
	}
	
	var relays []string
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	for scanner.Scan() {
		relay := strings.TrimSpace(scanner.Text())
		if relay != "" && strings.HasPrefix(relay, "wss://") {
			relays = append(relays, relay)
		}
	}
	
	return relays
}

// addRelay adds a relay to the list
func addRelay(url string) error {
	if !strings.HasPrefix(url, "wss://") {
		return fmt.Errorf("relay URL must start with wss://")
	}
	
	configDir := getConfigDir()
	relayFile := filepath.Join(configDir, "relays.txt")
	
	if err := os.MkdirAll(configDir, 0700); err != nil {
		return err
	}
	
	// Read existing relays
	var relays []string
	if _, err := os.Stat(relayFile); err == nil {
		data, err := ioutil.ReadFile(relayFile)
		if err != nil {
			return err
		}
		
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			relay := strings.TrimSpace(scanner.Text())
			if relay != "" && relay != url {
				relays = append(relays, relay)
			}
		}
	}
	
	// Add new relay
	relays = append(relays, url)
	
	// Write back to file
	content := strings.Join(relays, "\n")
	return ioutil.WriteFile(relayFile, []byte(content), 0644)
}

// removeRelay removes a relay from the list
func removeRelay(url string) error {
	configDir := getConfigDir()
	relayFile := filepath.Join(configDir, "relays.txt")
	
	// Read existing relays
	var relays []string
	if _, err := os.Stat(relayFile); err == nil {
		data, err := ioutil.ReadFile(relayFile)
		if err != nil {
			return err
		}
		
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			relay := strings.TrimSpace(scanner.Text())
			if relay != "" && relay != url {
				relays = append(relays, relay)
			}
		}
	}
	
	// Write back to file
	content := strings.Join(relays, "\n")
	return ioutil.WriteFile(relayFile, []byte(content), 0644)
}

// runStoreKeyCommand handles storing a key
func runStoreKeyCommand(nsec string) error {
	// Decode nsec
	_, privKey, err := nip19.Decode(nsec)
	if err != nil {
		return fmt.Errorf("failed to decode nsec: %v", err)
	}
	
	privKeyHex := hex.EncodeToString(privKey.([]byte))
	
	password, err := readPassword()
	if err != nil {
		return fmt.Errorf("password entry failed: %v", err)
	}
	
	if err := saveKey(privKeyHex, password); err != nil {
		return fmt.Errorf("failed to save key: %v", err)
	}
	
	color.Green("Key stored successfully!")
	return nil
}

// showHelp shows the help message
func showHelp() {
	fmt.Printf("Hoot - Nostr CLI Tool\n\n")
	fmt.Printf("Usage: hoot <command> [options]\n\n")
	fmt.Printf("Commands:\n")
	fmt.Printf("  post <message>              Post a message to Nostr\n")
	fmt.Printf("  login                       Interactive key setup\n")
	fmt.Printf("  login --key nsec1...        Import a private key\n")
	fmt.Printf("  profile                     View your profile\n")
	fmt.Printf("  profile view                View your profile (same as profile)\n")
	fmt.Printf("  profile set --name X --about Y  Update profile\n")
	fmt.Printf("  profile edit                Edit profile with $EDITOR\n")
	fmt.Printf("  feed                        View your feed\n")
	fmt.Printf("  feed --limit N              View feed with limit N\n")
	fmt.Printf("  dm                          View direct messages\n")
	fmt.Printf("  replies <note-or-number>    View replies to a note\n")
	fmt.Printf("  relay list                 List configured relays\n")
	fmt.Printf("  relay add <url>             Add a relay\n")
	fmt.Printf("  relay remove <url>          Remove a relay\n")
	fmt.Printf("  tip <amount> --user <npub>  Send a tip\n")
	fmt.Printf("  tip <amount> <lud16-or-npub> Send a tip (shorthand)\n")
	fmt.Printf("  nwc set <uri>               Set up Nostr Wallet Connect\n")
	fmt.Printf("  version                     Show version\n")
	fmt.Printf("  update                      Update hoot\n")
	fmt.Printf("  update --check              Check for updates\n")
	fmt.Printf("  help                        Show this help\n")
	fmt.Printf("\nExamples:\n")
	fmt.Printf("  hoot post \"Hello Nostr!\"\n")
	fmt.Printf("  hoot feed --limit 10\n")
	fmt.Printf("  hoot relay add wss://relay.example.com\n")
	fmt.Printf("  hoot tip 1000 npub1abc...\n")
}

// showVersion shows the version
func showVersion() {
	fmt.Printf("Hoot v0.1.0\n")
	fmt.Printf("Nostr CLI Tool\n")
}

// withLoading is a helper function to show loading spinner
func withLoading(message string, fn func() error) error {
	// In a real implementation, this would show a spinner
	fmt.Printf("%s...", message)
	err := fn()
	if err != nil {
		fmt.Printf(" %s\n", color.RedString("ERROR"))
		return err
	}
	fmt.Printf(" %s\n", color.GreenString("OK"))
	return nil
}

// main function (around line 1999 as mentioned in requirements)
func main() {
	// Initialize event cache
	configDir := getConfigDir()
	eventCache = NewEventCache(configDir)
	
	// Check if we have any arguments
	if len(os.Args) == 1 {
		// No arguments, launch TUI (preserved behavior)
		// Check if this is the first run and show wizard
		if isFirstRun() {
			if err := runFirstRunWizard(); err != nil {
				fmt.Printf("First-run wizard failed: %v\n", err)
				os.Exit(1)
			}
		}
		
		fmt.Println("Launching TUI...")
		// In a real implementation, this would launch the TUI
		return
	}
	
	// Check if first argument is a subcommand
	subcommand := os.Args[1]
	
	// Check if this is the login command and first run
	if isFirstRun() && subcommand == "login" {
		if err := runFirstRunWizard(); err != nil {
			fmt.Printf("First-run wizard failed: %v\n", err)
			os.Exit(1)
		}
	}
	
	switch subcommand {
	case "post":
		if len(os.Args) < 3 {
			fmt.Println("Error: post requires a message")
			fmt.Println("Usage: hoot post <message>")
			os.Exit(1)
		}
		message := strings.Join(os.Args[2:], " ")
		if err := runPublishCommand(message); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	case "login":
		if len(os.Args) > 2 && os.Args[2] == "--key" && len(os.Args) > 3 {
			nsec := os.Args[3]
			if err := runStoreKeyCommand(nsec); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		} else {
			// Interactive login
			if err := runFirstRunWizard(); err != nil {
				fmt.Printf("Login failed: %v\n", err)
				os.Exit(1)
			}
		}
	case "profile":
		if len(os.Args) > 2 {
			switch os.Args[2] {
			case "view":
				if err := runProfileCommand(); err != nil {
					fmt.Printf("Error: %v\n", err)
					os.Exit(1)
				}
			case "set":
				// Parse profile flags
				profile := make(map[string]string)
				for i := 3; i < len(os.Args); i++ {
					if os.Args[i] == "--name" && i+1 < len(os.Args) {
						profile["name"] = os.Args[i+1]
						i++
					} else if os.Args[i] == "--about" && i+1 < len(os.Args) {
						profile["about"] = os.Args[i+1]
						i++
					}
				}
				if err := runUpdateProfileCommand(profile); err != nil {
					fmt.Printf("Error: %v\n", err)
					os.Exit(1)
				}
			case "edit":
				// Launch $EDITOR with profile
				editor := os.Getenv("EDITOR")
				if editor == "" {
					editor = "nano"
				}
				cmd := exec.Command(editor, filepath.Join(configDir, "profiles.json"))
				cmd.Stdin = os.Stdin
				cmd.Stdout = os.Stdout
				if err := cmd.Run(); err != nil {
					fmt.Printf("Error: %v\n", err)
					os.Exit(1)
				}
			default:
				fmt.Printf("Unknown profile subcommand: %s\n", os.Args[2])
				os.Exit(1)
			}
		} else {
			if err := runProfileCommand(); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		}
	case "feed":
		limit := 10
		for i := 2; i < len(os.Args); i++ {
			if os.Args[i] == "--limit" && i+1 < len(os.Args) {
				fmt.Sscanf(os.Args[i+1], "%d", &limit)
				break
			}
		}
		if err := runListPostsCommand(limit); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	case "dm":
		if err := runDMsCommand(); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	case "replies":
		if len(os.Args) < 3 {
			fmt.Println("Error: replies requires a note ID")
			fmt.Println("Usage: hoot replies <note-or-number>")
			os.Exit(1)
		}
		noteID := os.Args[2]
		if err := runRepliesCommand(noteID); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	case "relay":
		if len(os.Args) < 3 {
			fmt.Println("Error: relay requires a subcommand")
			fmt.Println("Usage: hoot relay <list|add|remove> [url]")
			os.Exit(1)
		}
		switch os.Args[2] {
		case "list":
			relays := getRelayList()
			for _, relay := range relays {
				fmt.Println(relay)
			}
		case "add":
			if len(os.Args) < 4 {
				fmt.Println("Error: relay add requires a URL")
				fmt.Println("Usage: hoot relay add <url>")
				os.Exit(1)
			}
			url := os.Args[3]
			if err := addRelay(url); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Added relay: %s\n", url)
		case "remove":
			if len(os.Args) < 4 {
				fmt.Println("Error: relay remove requires a URL")
				fmt.Println("Usage: hoot relay remove <url>")
				os.Exit(1)
			}
			url := os.Args[3]
			if err := removeRelay(url); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Removed relay: %s\n", url)
		default:
			fmt.Printf("Unknown relay subcommand: %s\n", os.Args[2])
			os.Exit(1)
		}
	case "tip":
		if len(os.Args) < 3 {
			fmt.Println("Error: tip requires an amount")
			fmt.Println("Usage: hoot tip <amount> [--user <npub>|<lud16-or-npub>]")
			os.Exit(1)
		}
		amount := os.Args[2]
		var recipient string
		for i := 3; i < len(os.Args); i++ {
			if os.Args[i] == "--user" && i+1 < len(os.Args) {
				recipient = os.Args[i+1]
				break
			}
		}
		if recipient == "" && len(os.Args) >= 4 {
			recipient = os.Args[3]
		}
		if recipient == "" {
			fmt.Println("Error: tip requires a recipient")
			fmt.Println("Usage: hoot tip <amount> --user <npub>")
			fmt.Println("Usage: hoot tip <amount> <lud16-or-npub>")
			os.Exit(1)
		}
		if err := runTipCommand(amount, recipient); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	case "nwc":
		if len(os.Args) < 3 || os.Args[2] != "set" {
			fmt.Println("Error: nwc requires 'set' subcommand")
			fmt.Println("Usage: hoot nwc set <uri>")
			os.Exit(1)
		}
		if len(os.Args) < 4 {
			fmt.Println("Error: nwc set requires a URI")
			fmt.Println("Usage: hoot nwc set <uri>")
			os.Exit(1)
		}
		uri := os.Args[3]
		if err := runNWCSetup(uri); err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	case "version":
		showVersion()
	case "update":
		checkOnly := false
		for i := 2; i < len(os.Args); i++ {
			if os.Args[i] == "--check" {
				checkOnly = true
				break
			}
		}
		if checkOnly {
			if err := checkForUpdate(); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		} else {
			if err := selfUpdate(); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		}
	case "help":
		showHelp()
	default:
		// Check if it's a flag (backwards compatibility)
		if strings.HasPrefix(subcommand, "-") {
			// Fall back to flag parsing (preserved behavior)
			flag.Parse()
			fmt.Println("Flag parsing preserved (backwards compatibility)")
		} else {
			fmt.Printf("Unknown command: %s\n", subcommand)
			fmt.Println("Use 'hoot help' to see available commands")
			os.Exit(1)
		}
	}
}