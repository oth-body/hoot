# Hoot

Hoot is a command-line client for [Nostr](https://nostr.com). It supports posting, profiles, feeds, replies, direct messages, relay management, Lightning tips, and Nostr Wallet Connect setup.

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
