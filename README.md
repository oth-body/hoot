# Hoot

Hoot is a command-line client for [Nostr](https://nostr.com). It supports posting, profiles, feeds, replies, direct messages, relay management, Lightning tips, and Nostr Wallet Connect setup.

## Buzz interoperability

Hoot can publish directly to a [Buzz](https://github.com/block/buzz) relay. It
uses NIP-42 authentication when the relay challenges the client, sends channel
messages as NIP-29 kind `9` events with the required `h` channel tag, and sends
private messages as NIP-17 gift wraps. Buzz does not currently implement NIP-65
DM relay lists, so both NIP-17 copies are published to the selected Buzz relay.

```sh
# use a stored Hoot identity; the password is prompted for, never an argument
hoot buzz post --relay wss://buzz.example --channel <channel-uuid> "Hello"
hoot buzz post --relay wss://buzz.example --channel <channel-uuid> \
  --reply-to <parent-event-id> "Thread reply"
hoot buzz dm --relay wss://buzz.example --to npub1... "Private hello"
```

Set `BUZZ_RELAY_URL` to omit `--relay`. `buzz post` and `buzz dm` wait for the
relay's NIP-01 `OK` response and return an error on rejected publication.

## Install

Download the archive for your platform from [Releases](https://github.com/oth-body/hoot/releases), extract `hoot`, and put it on your `PATH`.

## Quick start

```sh
hoot login --key nsec1...
hoot post "Hello Nostr!"
hoot feed --limit 10
hoot profile
hoot relay list
```

The imported key is encrypted at rest under the platform config directory. Hoot prompts for the password when a command needs the key. Never pass private keys or passwords in shell history, logs, or automation output.

## Commands

Run `hoot help` for the complete list. Common commands include `post`, `login`, `profile`, `feed`, `dm`, `replies`, `relay`, `tip`, `nwc`, `version`, and `update`.

## Build from source

Requires Go 1.21 or newer:

```sh
git clone https://github.com/oth-body/hoot
cd hoot
go build -o hoot .
./hoot version
```

## License

MIT. See [LICENSE](LICENSE).
