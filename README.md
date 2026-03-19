# hoot - A Nostr CLI Tool

A simple command-line tool for using the Nostr network. It keeps your keys safe, lets you manage your profile, and supports multiple relays. It's made for fun, not serious use.

## Features

- Safe storage of private keys
- Post messages to multiple relays
- View and edit profile information (editing is still being worked on)
- List recent posts
- Customizable relay list

## Screenshots

<p align="center">
  <img src="assets/login.png" width="45%" />
  <img src="assets/home.png" width="45%" />
</p>
<p align="center">
  <img src="assets/feed.png" width="91%" />
</p>

## Prerequisites

- Go 1.19 or later
- Git

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/oth-body/hoot.git
   cd hoot
   ```

2. Install dependencies:

   ```bash
   go mod download
   ```

3. Build the binary:

   ```bash
   go build -o hoot
   ```

4. (Optional) Move the binary to your PATH:

   ```bash
   # Linux/macOS
   sudo mv hoot /usr/local/bin/

   # Windows
   # Move hoot.exe to a directory in your PATH
   ```

## Configuration

### Relay Configuration

Create a `relays.txt` file  in:

- Your config directory:
  - Linux: `~/.config/nostr-cli/`
  - macOS: `~/Library/Application Support/nostr-cli/`
  - Windows: `%APPDATA%\nostr-cli\`

Example `relays.txt`:

```text
wss://relay.damus.io
wss://relay.nostr.band
wss://nostr.wine
```

If no `relays.txt` is found, the above default relays will be used.

## Usage

Hoot can be used in two modes: **Interactive TUI** (Terminal User Interface) or **CLI** (Command Line Interface).

### Interactive TUI Mode

Simply run `hoot` without any flags to launch the interactive terminal interface:

```bash
hoot
```

The TUI provides:

- **Login options**: Enter nsec directly, use saved profile, or scan QR code (NIP-46)
- **Multi-profile support**: Save and switch between multiple Nostr accounts
- **Post composer**: Write and publish notes
- **Feed viewer**: Browse recent posts from the network
- **Relay management**: Add, remove, and configure relays
- **Tipping**: Send sats to other users via Lightning

#### TUI Navigation

- Use **↑/↓ arrow keys** to navigate menus
- Press **Enter** to select an option
- Press **Esc** to go back
- Press **q** to quit

---

### CLI Mode

Use command-line flags for scripting or quick actions.

#### Store Your Private Key

```bash
hoot -s -k <your-private-key>
```

You'll be prompted to create an encryption password.

#### View Your Public Key

```bash
hoot
```

#### Post a Message

```bash
hoot -m "Hello Nostr! #introduction"
```

Hashtags are automatically extracted and added as tags.

#### List Recent Posts

```bash
hoot -l
```

#### View Profile

```bash
hoot -p
```

#### Update Profile

```bash
hoot -u '{"name":"Alice","about":"Nostr enthusiast","lud16":"alice@getalby.com"}'
```

#### Using Custom Relays for a Single Command

```bash
hoot -r "wss://relay1.com,wss://relay2.com" -m "Hello from custom relays!"
```

---

### Common Workflows

#### Complete Setup

```bash
# 1. Store your key
hoot -s -k nsec1...

# 2. Configure custom relays
cat > ~/.config/nostr-cli/relays.txt << EOF
wss://relay.damus.io
wss://relay.nostr.band
wss://nostr.wine
EOF

# 3. Post introduction
hoot -m "Hello Nostr! #introduction"
```

#### Post with Hashtags and Custom Relays

```bash
hoot -r "wss://my-relay.com,wss://backup-relay.com" \
     -m "Just deployed hoot v0.0.4! 🎉 #go #nostr #opensource"
```

#### View and Reply

```bash
# See your recent posts
hoot -l

# View replies to a specific note
hoot -replies note1abc123...

# View your DMs
hoot -dms
```

#### Profile Management

```bash
# View your profile
hoot -p

# Update with Lightning address
hoot -u '{"name":"Alice","about":"Building on Nostr","lud16":"alice@getalby.com"}'

# Full profile update
hoot -u '{
  "name": "Alice Nostr",
  "about": "Building on Nostr | Go developer",
  "picture": "https://example.com/profile.png",
  "banner": "https://example.com/banner.png",
  "lud16": "alice@getalby.com",
  "nip05": "alice@example.com"
}'
```

---

### Tipping with NWC (Nostr Wallet Connect)

Hoot supports sending Lightning tips via NWC.

#### Set up your NWC wallet

```bash
hoot -nwc "nostr+walletconnect://..."
```

Get your NWC URI from a compatible wallet like Alby or Mutiny.

#### Send a tip

```bash
# Tip by npub
hoot -tip 100 -user npub1...

# Tip by hex pubkey
hoot -tip 100 -user <hex-pubkey>

# Tip directly to a Lightning address
hoot -tip 100 -user alice@getalby.com

# Larger tip to a Nostr user
hoot -tip 1000 -user npub1abc123...
```

---

### NIP-89 App Handlers

Register your app as a handler for specific event kinds:

```bash
# Register for note handling (kind 1) and reposts (kind 6)
hoot -register-handler "1,6" -platform web -url-template "https://myapp.com/e/<bech32>"
```

Recommend an app for handling a kind:

```bash
hoot -recommend "pubkey:d-identifier:1"
```

Find handlers for a specific kind:

```bash
# Find apps that handle kind 1 (text notes)
hoot -find-handlers 1
```

---

### All CLI Flags

| Flag | Description |
| ---- | ----------- |
| `-m "message"` | Post a message to Nostr |
| `-k <key>` | Private key to store (use with `-s`) |
| `-s` | Store a new private key |
| `-r "relay1,relay2"` | Comma-separated list of relay URLs |
| `-l` | List your last 4 posts |
| `-p` | View your profile info |
| `-u '{"name":"..."}` | Update profile with JSON |
| `-dms` | View your direct messages |
| `-replies "event-id"` | View replies/reactions for a specific event |
| `-version` | Display version info |
| `-nwc "uri"` | Set NWC URI for tipping |
| `-tip <sats>` | Amount to tip (use with `-user`) |
| `-user <npub/hex/lud16>` | User to tip |
| `-register-handler "kinds"` | Register as handler for event kinds |
| `-platform <platform>` | Platform for handler (web, ios, android) |
| `-url-template "url"` | URL template for handler |
| `-recommend "pk:d:kind"` | Recommend an app for a kind |
| `-find-handlers <kind>` | Find handlers for a specific kind |

---

### Environment Variables

| Variable | Description |
| -------- | ----------- |
| `HOOT_PASSWORD` | Encryption password (for automation/scripting) |
