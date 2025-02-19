# hoot

A secure command-line interface for interacting with the Nostr protocol. Post messages, manage your profile, and interact with multiple relays while keeping your private key encrypted locally.

## Features

- 🔒 Secure key management with scrypt-based encryption
- 📝 Create and publish posts with automatic hashtag detection
- 👤 View and update profile information
- 🔄 Multi-relay support with configurable relay list
- 📜 View recent post history
- 🌐 Cross-platform support (Windows, macOS, Linux)

## Installation

```bash
go install github.com/oth-body/hoot@latest
```

## Quick Start

1. Store your private key (you'll be prompted for an encryption password):
```bash
hoot -s -k "your-private-key"
```

2. Make your first post:
```bash
hoot -m "Hello Nostr! #introduction"
```

## Configuration

### Relay Configuration

The tool looks for relay URLs in the following order:
1. Local `relays.txt` in the current directory
2. System config directory:
   - Windows: `%APPDATA%/hoot/relays.txt`
   - macOS: `~/Library/Application Support/hoot/relays.txt`
   - Linux: `~/.config/hoot/relays.txt`

Create a `relays.txt` file with one relay URL per line:
```
wss://relay.damus.io
wss://relay.nostr.band
wss://nostr.wine
```

## Usage

### View Your Public Key
```bash
hoot
```

### Post a Message
```bash
hoot -m "Your message here #nostr"
```

### View Profile
```bash
hoot -p
```

### Update Profile
```bash
hoot -u '{"name":"Your Name","about":"Your bio"}'
```

### List Recent Posts
```bash
hoot -l
```

### Use Custom Relays for a Single Command
```bash
hoot -r "wss://relay1.com,wss://relay2.com" -m "Your message"
```

## Security

- Private keys are encrypted using XSalsa20-Poly1305
- Key derivation uses scrypt for password-based encryption
- Keys are stored in the system's config directory with appropriate permissions
- Password is required for every command that needs the private key

## Building from Source

```bash
git clone https://github.com/oth-body/hoot
cd hoot
go build
```

## Dependencies

- github.com/nbd-wtf/go-nostr: Nostr protocol implementation
- golang.org/x/crypto: Cryptographic functions
- Standard Go libraries

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License 
