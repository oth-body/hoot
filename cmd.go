package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Command represents a subcommand
type Command struct {
	Name        string
	Description string
	Handler     func(args []string) error
	MinArgs     int
	MaxArgs     int
	Usage       string
}

// CommandRegistry holds all available commands
type CommandRegistry struct {
	commands map[string]*Command
}

// NewCommandRegistry creates a new command registry
func NewCommandRegistry() *CommandRegistry {
	return &CommandRegistry{
		commands: make(map[string]*Command),
	}
}

// Register adds a command to the registry
func (r *CommandRegistry) Register(cmd *Command) {
	r.commands[cmd.Name] = cmd
}

// Get returns a command by name
func (r *CommandRegistry) Get(name string) *Command {
	return r.commands[name]
}

// GetAll returns all commands
func (r *CommandRegistry) GetAll() map[string]*Command {
	return r.commands
}

// Help shows help for all commands or a specific command
func (r *CommandRegistry) Help(commandName string) {
	if commandName != "" {
		cmd := r.Get(commandName)
		if cmd == nil {
			fmt.Printf("Unknown command: %s\n", commandName)
			return
		}
		fmt.Printf("Usage: hoot %s\n", cmd.Usage)
		fmt.Printf("Description: %s\n", cmd.Description)
		return
	}

	fmt.Printf("Hoot - Nostr CLI Tool\n\n")
	fmt.Printf("Usage: hoot <command> [options]\n\n")
	fmt.Printf("Commands:\n")
	
	for _, cmd := range r.commands {
		fmt.Printf("  %-25s %s\n", cmd.Name, cmd.Description)
	}
	
	fmt.Printf("\nUse 'hoot help <command>' for more information on a specific command.\n")
	fmt.Printf("Use 'hoot help' to show this message.\n")
}

// ParseAndExecute parses command line arguments and executes the appropriate command
func (r *CommandRegistry) ParseAndExecute(args []string) bool {
	if len(args) == 0 {
		return false // No command, should fall back to TUI
	}

	commandName := args[0]
	cmd := r.Get(commandName)
	
	if cmd == nil {
		// Check if it's a flag (backwards compatibility)
		if strings.HasPrefix(commandName, "-") {
			return false // Fall back to flag parsing
		}
		
		fmt.Printf("Unknown command: %s\n", commandName)
		fmt.Printf("Use 'hoot help' to see available commands.\n")
		os.Exit(1)
		return true
	}

	// Check argument count
	if len(args)-1 < cmd.MinArgs {
		fmt.Printf("Error: %s requires at least %d argument(s)\n", cmd.Name, cmd.MinArgs)
		fmt.Printf("Usage: hoot %s\n", cmd.Usage)
		os.Exit(1)
		return true
	}
	
	if cmd.MaxArgs > 0 && len(args)-1 > cmd.MaxArgs {
		fmt.Printf("Error: %s accepts at most %d argument(s)\n", cmd.Name, cmd.MaxArgs)
		fmt.Printf("Usage: hoot %s\n", cmd.Usage)
		os.Exit(1)
		return true
	}

	// Execute command
	if err := cmd.Handler(args[1:]); err != nil {
		fmt.Printf("Error: %s\n", err)
		os.Exit(1)
		return true
	}

	return true
}

// Command handlers

// handlePost handles the post command
func handlePost(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("post requires a message")
	}
	message := strings.Join(args, " ")
	return runPublishCommand(message)
}

// handleLogin handles the login command
func handleLogin(args []string) error {
	if len(args) > 0 && args[0] == "--key" && len(args) > 1 {
		return runStoreKeyCommand(args[1])
	}
	// Interactive login
	return runFirstRunWizard()
}

// handleProfile handles the profile command and its subcommands
func handleProfile(args []string) error {
	if len(args) == 0 {
		return runProfileCommand()
	}

	switch args[0] {
	case "view":
		return runProfileCommand()
	case "set":
		// Parse profile flags
		profile := make(map[string]string)
		for i := 1; i < len(args); i++ {
			if args[i] == "--name" && i+1 < len(args) {
				profile["name"] = args[i+1]
				i++
			} else if args[i] == "--about" && i+1 < len(args) {
				profile["about"] = args[i+1]
				i++
			}
		}
		return runUpdateProfileCommand(profile)
	case "edit":
		// Launch $EDITOR with profile
		configDir := getConfigDir()
		editor := os.Getenv("EDITOR")
		if editor == "" {
			editor = "nano"
		}
		cmd := exec.Command(editor, filepath.Join(configDir, "profiles.json"))
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		return cmd.Run()
	default:
		return fmt.Errorf("unknown profile subcommand: %s", args[0])
	}
}

// handleFeed handles the feed command
func handleFeed(args []string) error {
	limit := 10
	for i := 0; i < len(args); i++ {
		if args[i] == "--limit" && i+1 < len(args) {
			fmt.Sscanf(args[i+1], "%d", &limit)
			break
		}
	}
	return runListPostsCommand(limit)
}

// handleDM handles the dm command
func handleDM(args []string) error {
	return runDMsCommand()
}

// handleReplies handles the replies command
func handleReplies(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("replies requires a note ID")
	}
	return runRepliesCommand(args[0])
}

// handleRelay handles the relay command and its subcommands
func handleRelay(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("relay requires a subcommand (list, add, remove)")
	}

	switch args[0] {
	case "list":
		relays := getRelayList()
		for _, relay := range relays {
			fmt.Println(relay)
		}
		return nil
	case "add":
		if len(args) < 2 {
			return fmt.Errorf("relay add requires a URL")
		}
		url := args[1]
		if err := addRelay(url); err != nil {
			return err
		}
		fmt.Printf("Added relay: %s\n", url)
		return nil
	case "remove":
		if len(args) < 2 {
			return fmt.Errorf("relay remove requires a URL")
		}
		url := args[1]
		if err := removeRelay(url); err != nil {
			return err
		}
		fmt.Printf("Removed relay: %s\n", url)
		return nil
	default:
		return fmt.Errorf("unknown relay subcommand: %s", args[0])
	}
}

// handleTip handles the tip command
func handleTip(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("tip requires an amount and recipient")
	}
	
	amount := args[0]
	var recipient string
	
	// Check if --user flag is used
	for i := 1; i < len(args); i++ {
		if args[i] == "--user" && i+1 < len(args) {
			recipient = args[i+1]
			break
		}
	}
	
	// If no --user flag, assume second argument is recipient
	if recipient == "" {
		recipient = args[1]
	}
	
	return runTipCommand(amount, recipient)
}

// handleNWC handles the nwc command
func handleNWC(args []string) error {
	if len(args) == 0 || args[0] != "set" {
		return fmt.Errorf("nwc requires 'set' subcommand")
	}
	if len(args) < 2 {
		return fmt.Errorf("nwc set requires a URI")
	}
	return runNWCSetup(args[1])
}

// handleUpdate handles the update command
func handleUpdate(args []string) error {
	checkOnly := false
	for _, arg := range args {
		if arg == "--check" {
			checkOnly = true
			break
		}
	}
	
	if checkOnly {
		return checkForUpdate()
	}
	return selfUpdate()
}

// handleHelp handles the help command
func handleHelp(args []string) error {
	var commandName string
	if len(args) > 0 {
		commandName = args[0]
	}
	
	registry := NewCommandRegistry()
	registerCommands(registry)
	registry.Help(commandName)
	return nil
}

// handleVersion handles the version command
func handleVersion(args []string) error {
	showVersion()
	return nil
}

// registerCommands registers all available commands
func registerCommands(registry *CommandRegistry) {
	registry.Register(&Command{
		Name:        "post",
		Description: "Post a message to Nostr",
		Handler:     handlePost,
		MinArgs:     1,
		MaxArgs:     -1, // Unlimited arguments
		Usage:       "post <message>",
	})

	registry.Register(&Command{
		Name:        "login",
		Description: "Interactive key setup or import a private key",
		Handler:     handleLogin,
		MinArgs:     0,
		MaxArgs:     2, // login or login --key nsec1...
		Usage:       "login [--key nsec1...]",
	})

	registry.Register(&Command{
		Name:        "profile",
		Description: "View or update your profile",
		Handler:     handleProfile,
		MinArgs:     0,
		MaxArgs:     5, // profile, profile view, profile set --name X --about Y, profile edit
		Usage:       "profile [view|set|edit]",
	})

	registry.Register(&Command{
		Name:        "feed",
		Description: "View your feed",
		Handler:     handleFeed,
		MinArgs:     0,
		MaxArgs:     2, // feed or feed --limit N
		Usage:       "feed [--limit N]",
	})

	registry.Register(&Command{
		Name:        "dm",
		Description: "View direct messages",
		Handler:     handleDM,
		MinArgs:     0,
		MaxArgs:     0,
		Usage:       "dm",
	})

	registry.Register(&Command{
		Name:        "replies",
		Description: "View replies to a note",
		Handler:     handleReplies,
		MinArgs:     1,
		MaxArgs:     1,
		Usage:       "replies <note-or-number>",
	})

	registry.Register(&Command{
		Name:        "relay",
		Description: "Manage relay configuration",
		Handler:     handleRelay,
		MinArgs:     1,
		MaxArgs:     2,
		Usage:       "relay <list|add|remove> [url]",
	})

	registry.Register(&Command{
		Name:        "tip",
		Description: "Send a tip",
		Handler:     handleTip,
		MinArgs:     2,
		MaxArgs:     3,
		Usage:       "tip <amount> [--user <npub>|<lud16-or-npub>]",
	})

	registry.Register(&Command{
		Name:        "nwc",
		Description: "Set up Nostr Wallet Connect",
		Handler:     handleNWC,
		MinArgs:     2,
		MaxArgs:     2,
		Usage:       "nwc set <uri>",
	})

	registry.Register(&Command{
		Name:        "update",
		Description: "Update hoot or check for updates",
		Handler:     handleUpdate,
		MinArgs:     0,
		MaxArgs:     1,
		Usage:       "update [--check]",
	})

	registry.Register(&Command{
		Name:        "help",
		Description: "Show help information",
		Handler:     handleHelp,
		MinArgs:     0,
		MaxArgs:     1,
		Usage:       "help [command]",
	})

	registry.Register(&Command{
		Name:        "version",
		Description: "Show version information",
		Handler:     handleVersion,
		MinArgs:     0,
		MaxArgs:     0,
		Usage:       "version",
	})
}

// ExecuteCommand parses and executes a command from command line arguments
func ExecuteCommand() bool {
	registry := NewCommandRegistry()
	registerCommands(registry)
	
	return registry.ParseAndExecute(os.Args[1:])
}