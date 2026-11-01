# hoot - a Nostr client for your terminal

Read and post on Nostr, reply, like and zap, and send private DMs, all from the command line. Run `hoot` for a full-screen TUI, or use flags (`hoot -m "gm"`) for scripts. It's a hobby project, made for fun.

📖 **Full documentation: https://hoot-docs.vercel.app**

## Features

- **Two ways to sign in**: import an `nsec` (encrypted locally with your password), or scan a QR code with [Amber](https://github.com/greenart7c3/Amber) so your key stays on your phone (NIP-46). Amber pairings are remembered ("Continue as…").
- **Multiple accounts**: save, switch between and delete profiles
- **Feed**: global or following, with author names and threads; **reply, like and zap** the selected post
- **Private DMs (NIP-17)**: read and send gift-wrapped messages (and read legacy NIP-04 DMs), with a local key or with Amber
- **Zaps and tips in sats** through any Nostr Wallet Connect wallet (NIP-47, NIP-44 when supported). Zaps (NIP-57) show up on Nostr; hoot waits for the wallet to confirm and refuses invoices for the wrong amount
- **Fast and responsive**: relays are queried in parallel, and loading never freezes the screen
- **Manage relays** in the app, even before signing in
- **NIP-89** app-handler commands

## Screenshots

<p align="center">
  <img src="assets/feed.webp" alt="The global feed: posts in bordered boxes with author names, the selected post's note ID, and key hints for reply, like and zap" width="90%" />
</p>
<p align="center">
  <img src="assets/thread.webp" alt="A thread: the original post at the top, then its replies and reactions" width="45%" />
  <img src="assets/dms.webp" alt="Direct messages: private NIP-17 messages marked with a lock, and an older NIP-04 message" width="45%" />
</p>
<p align="center">
  <img src="assets/home.webp" alt="The home screen: the profile's npub and the menu" width="45%" />
  <img src="assets/tip-paid.webp" alt="The tip screen after paying 21 sats to a Lightning address" width="45%" />
</p>

More screenshots, step by step, in the [documentation](https://hoot-docs.vercel.app).

## Install

Download a prebuilt binary for Linux, macOS or Windows from [Releases](https://github.com/oth-body/hoot/releases), or build from source with **Go 1.26+**:

```bash
git clone https://github.com/oth-body/hoot.git
cd hoot
go build -o hoot .
sudo mv hoot /usr/local/bin/   # optional (Linux/macOS)
```

## Quick Start

```bash
hoot                                   # open the TUI: add a profile or scan with Amber
hoot -m "Hello Nostr! #introduction"   # post from the command line
hoot -nwc "nostr+walletconnect://..."  # connect a wallet (once)
hoot -tip 21 -user alice@getalby.com   # send a tip
hoot -dm npub1... -m "hi"              # send a private message
hoot -set about="new bio"              # change one profile field
```

In the TUI: **↑/↓** or **j/k** to move, **Enter** to select, **Esc** to go back, **Ctrl+C** to quit. On the home screen the letter shown next to each item is its shortcut (`p` post, `f` feed, `d` DMs, `e` replies, `t` tip, `r` relays, `s` switch profile, `q` quit).

## Usage

### TUI

Run `hoot` with no arguments. From the home screen you can post, view the feed, view DMs, look up replies and reactions to a note, tip someone, manage relays, and switch profiles. Your full npub is shown under your name.

- **Feed**: `g` switches global/following; ↑/↓ selects a post; Enter opens its thread; `r` reply, `+` like, `z` zap.
- **DMs**: `n` new private message, `r` reply. 🔒 marks private (NIP-17) messages.
- **Login screen**: `x` deletes the highlighted profile (or forgets the saved Amber session).

Signing in with Amber: choose **Scan QR with Amber** and scan the code with the Amber app. Your name, NIP-05 and bio appear on the home screen, and next time **Continue as NAME (Amber)** reconnects without a QR code. Everything works with Amber, including DMs and zaps.

### CLI

The CLI uses the key stored with `hoot -s -k <nsec>` if there is one, otherwise the TUI profile you last used. It prompts for the password, or reads it from `HOOT_PASSWORD`.

| Flag | Description |
| ---- | ----------- |
| `-m "text"` | Post a note (`#hashtags` become `t` tags) |
| `-r "url1,url2"` | Relays to use for `-m` / `-u` / `-set` instead of your saved list |
| `-l` | Show your last 4 notes |
| `-p` | Show your profile (kind 0) JSON |
| `-set key=value` | Change one profile field and keep the rest (repeatable; empty value removes it) |
| `-u '<json>'` | Publish a whole new profile. **Replaces everything**, so prefer `-set` |
| `-dms` | Show your DMs (private NIP-17 and legacy NIP-04) |
| `-dm <npub> -m "text"` | Send a private DM (NIP-17) |
| `-replies <id>` | Show replies/reactions to a note (`note1…`, `nevent1…` or hex) |
| `-s -k <nsec>` | Store a private key, encrypted with a password |
| `-nwc "uri"` | Save your Nostr Wallet Connect connection string |
| `-tip <sats> -user <who>` | Tip a Lightning address, npub or hex pubkey |
| `-register-handler "kinds"` | NIP-89: announce a handler app (with `-url-template`, `-platform`) |
| `-recommend "pk:d:kind"` | NIP-89: recommend a handler app |
| `-find-handlers <kind>` | NIP-89: list handler apps for a kind |
| `-npub` | Print your npub (no password needed for TUI profiles) |
| `-version` | Print version info |

See the [CLI reference](https://hoot-docs.vercel.app/cli-reference/) for details and examples.

### Tipping

1. In your wallet (e.g. Alby Hub), create an app connection that can send payments and copy its `nostr+walletconnect://` string.
2. `hoot -nwc "<that string>"`
3. Zap a post from the feed (`z`), tip from the TUI (**[t] Tip someone**), or use `hoot -tip <sats> -user <who>`.

Hoot waits up to 60 seconds for the wallet's confirmation. If it times out, the payment may still complete, so check your wallet before retrying. More in the [tipping guide](https://hoot-docs.vercel.app/wallet-connect/).

## Configuration

Hoot keeps its files in:

| OS | Directory |
| -- | --------- |
| Linux | `$XDG_CONFIG_HOME/hoot/` (usually `~/.config/hoot/`) |
| macOS | `~/Library/Application Support/hoot/` |
| Windows | `%APPDATA%\hoot\` |

| File | Contents |
| ---- | -------- |
| `profiles.json` | Saved profiles (private keys encrypted with scrypt + NaCl secretbox) |
| `nostr_key.enc` | Key stored with `hoot -s` |
| `relays.txt` | Relay list, one URL per line (`//` comments allowed). A `relays.txt` in the current directory takes precedence. |
| `nwc.txt` | Wallet connection string. **Keep private**: it can spend from the connection. |
| `amber_session.json` | Saved Amber pairing (lets this computer ask Amber to sign). **Keep private.** |
| `hoot_cache.db` | Cache of recent posts and profiles (safe to delete) |

Default relays, used when there's no `relays.txt`. All three are free, general-purpose relays that accept posts from anyone:

```text
wss://relay.damus.io
wss://nos.lol
wss://relay.primal.net
```

To use your own, copy [`relays.example.txt`](relays.example.txt) to `relays.txt` in the config directory and edit it, or manage relays from the TUI (**[r] Manage Relays**). Pick free relays unless you've paid for one: paid relays let anyone read but reject posts from non-members.

| Environment variable | Description |
| -------------------- | ----------- |
| `HOOT_PASSWORD` | Password for your stored key, for scripts. Environment variables can leak, so prefer feeding it from a password manager. |

## Development

```bash
go test ./...                 # unit + end-to-end tests (in-process relay; no network needed)
go test -race ./...           # same, with the race detector
go vet ./...
```

CI also runs `govulncheck`.

## License

MIT. See [LICENSE](LICENSE).
