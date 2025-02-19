# hoot - A Nostr CLI Tool

A secure command-line interface for interacting with the Nostr network. Features encrypted key storage, profile management, and multi-relay support. Made for shenanigans,not for serious critical use

## Features

- Secure encrypted storage of private keys
- Post messages to multiple relays
- View and edit profile information
- List recent posts
- Configurable relay list
- Automatic hashtag detection
- Cross-platform support (Windows, macOS, Linux)

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

Create a `relays.txt` file either in:
- The current directory, or
- Your config directory:
  - Linux: `~/.config/nostr-cli/`
  - macOS: `~/Library/Application Support/nostr-cli/`
  - Windows: `%APPDATA%\nostr-cli\`

Example `relays.txt`:
```
wss://relay.damus.io
wss://relay.nostr.band
wss://nostr.wine
```

If no `relays.txt` is found, default relays will be used.

## Usage

### Store Your Private Key

```bash
hoot -s -k <your-private-key>
```
You'll be prompted to create an encryption password.

### View Your Public Key

```bash
hoot
```

### Post a Message

```bash
hoot -m "Hello Nostr! #introduction"
```

### List Recent Posts

```bash
hoot -l
```

### View Profile

```bash
hoot -p
```

### Update Profile

```bash
hoot -u '{"name":"Alice","about":"Nostr enthusiast"}'
```

### Using Custom Relays for a Single Command

```bash
hoot -r "wss://relay1.com,wss://relay2.com" -m "Hello from custom relays!"
```

## Security

- Private keys are encrypted using XSalsa20 and Poly1305
- Key derivation uses Scrypt
- Keys are stored in your system's config directory with appropriate permissions


## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
