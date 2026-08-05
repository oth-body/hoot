# CLAUDE.md

Guidance for AI assistants working in this repository.

## What this is

Hoot is a single-binary command-line client for [Nostr](https://nostr.com), written in Go.
Module name `hoot`, package `main`, no subpackages — every `.go` file sits in the repo root.

The binary covers posting, profiles, feeds, replies, DMs, relay management, Lightning tips,
Nostr Wallet Connect, and publishing to a [Buzz](https://github.com/block/buzz) relay.

## Build, test, run

```sh
go build -o hoot .      # build (Go 1.25.0 per go.mod; README says 1.21+)
go test ./...           # unit tests — all live in buzz_test.go
go vet ./...
gofmt -l .              # must print nothing
./hoot version
```

There is **no CI workflow that runs tests**. `.github/workflows/release.yml` only fires on
`v*.*.*` tags and runs GoReleaser. Run `go test ./...`, `go vet ./...`, and `gofmt -l .`
yourself before committing — nothing else will.

`*hoot` is in `.gitignore`, so a `go build -o hoot .` artifact will not be accidentally committed.
Never commit built binaries.

## Repository layout

| File | Contents |
| --- | --- |
| `hoot.go` | `main()`, the real command dispatch, config/key management, crypto, first-run wizard, relay file I/O, and stubbed command implementations |
| `cmd.go` | `CommandRegistry` — a second, **currently unreachable** dispatch layer (see below) |
| `buzz.go` | Buzz relay integration: NIP-42 auth, NIP-29 channel posts, NIP-17 gift-wrapped DMs. The only fully implemented network feature |
| `buzz_test.go` | Tests for password-source parsing and Buzz argument validation |
| `.goreleaser.yml` | Multi-platform release: archives, snap, scoop, AUR, deb/rpm, changelog grouping |
| `.github/workflows/release.yml` | Tag-triggered GoReleaser run |

## Architecture: two dispatchers, only one live

This is the single most important thing to understand before editing commands.

**`main()` in `hoot.go:776` is the live dispatcher.** It is a hand-written `switch` over
`os.Args[1]` covering `buzz`, `post`, `login`, `profile`, `feed`, `dm`, `replies`, `relay`,
`tip`, `nwc`, `version`, `update`, and `help`.

**`cmd.go`'s `CommandRegistry` is dead code.** `ExecuteCommand()` (`cmd.go:423`) is never
called from anywhere. The registry is reachable only through `handleHelp`, which is itself
only registered inside that same registry — a closed loop. It compiles and is kept in tree,
but nothing in it executes.

Consequences to keep in mind:

- Adding a command to `registerCommands()` alone changes **nothing** at runtime.
- The `help` command runs `showHelp()` (`hoot.go:714`), a hand-maintained `fmt.Printf` block —
  **not** `CommandRegistry.Help()`.
- `buzz` exists only in `main()`'s switch and in `showHelp()`; it was never added to the registry.
- The `profile`, `relay`, `tip`, `nwc`, `feed`, and `update` argument parsing is **duplicated**
  between `main()` and `cmd.go` handlers. A behavior change in one place does not propagate.

**When adding or changing a command:** edit the `switch` in `main()` and update `showHelp()`.
Mirroring the change into `cmd.go` is optional and only worth doing if you are deliberately
keeping the two in sync. Do not delete `cmd.go` or wire up `ExecuteCommand()` without asking —
that is a design decision, not a cleanup.

## Implementation status

Most commands in `hoot.go` are **stubs that print a colored message and return `nil`** —
`runPublishCommand`, `runProfileCommand`, `runUpdateProfileCommand`, `runListPostsCommand`,
`runDMsCommand`, `runRepliesCommand`, `runTipCommand`, `runNWCSetup`, `selfUpdate`,
`checkForUpdate`. They carry `// In a real implementation, ...` comments.

Genuinely working today:

- Key storage, encryption, and decryption (`saveKey`, `loadAndDecodeKey`, `encryptKey`, `decryptKey`)
- Password sourcing (`configurePasswordInput`, `readPassword`)
- Relay list file management (`getRelayList`, `addRelay`, `removeRelay`)
- The first-run wizard (`runFirstRunWizard` and its `handle*` helpers)
- Everything in `buzz.go`

Also inert placeholders: `EventCache` (holds only a path, never reads or writes),
`nip46Session`, `localPrivateKey`, the `timeouts` struct, and `withLoading`.
`handleNIP46Connect` prints "will be implemented in a future version".

Do not assume a command works because it is listed in help. Read the function first.

## Security conventions

These are load-bearing — the repo has clearly been shaped around them.

**Never accept a password or private key as a command-line argument.** Process arguments leak
into `ps`, shell history, and CI logs. `configurePasswordInput` (`hoot.go:86`) is the only
entry point for password input and accepts exactly one of:

1. `HOOT_PASSWORD` environment variable
2. `--password-stdin`
3. `--password-file <path>`

If none is given, `readPassword` (`hoot.go:117`) prompts on the terminal with echo disabled.
Supplying more than one source is a hard error — including a repeated `--password-file`,
and including `HOOT_PASSWORD` being *set but empty* (it is detected with `os.LookupEnv`, so
an empty value still counts as a source and still resolves to an empty password).

`configurePasswordInput` runs in `main()` **before** dispatch, strips the password flags out
of the argument slice, and rewrites `os.Args`. This is why the flags may appear before or
after the subcommand. Exit code on a password-source conflict is `4`; every other error path
exits `1`.

**Key storage.** The private key is stored hex-encoded, encrypted with AES-GCM under a key
derived as `sha256(password)`, at `<configDir>/nostr_key.enc` with mode `0600`. The ciphertext
is serialized as `v1:` + raw-std-base64 of `nonce || sealed`. `decryptKey` rejects anything
without the `v1:` prefix and tells the user to re-import. If you change the format, bump the
prefix and keep the old path readable.

Note that `sha256(password)` is not a password-based KDF. If you are asked to harden this,
introduce `v2:` with a real KDF (scrypt/argon2 — `golang.org/x/crypto` is already a
dependency) and keep `v1:` decryption for migration.

**Never print keys, passwords, or decrypted material** outside the explicit backup flow in
`handleGenerateKey`, which shows the freshly generated nsec once and requires the user to type
`backup` to confirm.

## Config directory

`getConfigDir()` (`hoot.go:57`) resolves via `$HOME`, not `os.UserConfigDir`:

- macOS: `~/Library/Application Support/hoot`
- Linux and everything else: `~/.config/hoot`

Files it manages:

| File | Mode | Purpose |
| --- | --- | --- |
| `nostr_key.enc` | 0600 | Encrypted private key |
| `profiles.json` | 0600 | Local profile data (not yet published to Nostr) |
| `relays.txt` | 0644 | Newline-separated relay URLs |
| `.guest` | 0600 | Marker written when the user skips the first-run wizard |
| `cache.db` | — | Path computed by `EventCache`, never actually created |

`isFirstRun()` returns true when neither `nostr_key.enc` nor `profiles.json` exists and
`.guest` is absent. The wizard fires on a bare `hoot` invocation and on `hoot login`.

Relay entries are only accepted and returned when they start with `wss://` — `addRelay`
rejects anything else, and `getRelayList` silently filters non-`wss://` lines while reading.
Note that `getRelayList` returns the three built-in defaults (`relay.damus.io`,
`relay.nostr.band`, `nos.lol`) when the file is missing or unreadable.

## Buzz integration (`buzz.go`)

The one place with real Nostr networking, using `github.com/nbd-wtf/go-nostr`.

- Relay URL comes from `--relay` or `BUZZ_RELAY_URL`; `ws://` and `wss://` are both accepted
  here (unlike the general relay list, which is `wss://`-only).
- Channel posts are `nostr.KindTextNote` events carrying the NIP-29 `h` tag with the channel
  UUID; `--reply-to` appends an `["e", <id>, "", "reply"]` tag.
- `publishBuzzEvent` publishes optimistically, and on an error containing `auth-required:`
  performs NIP-42 `relay.Auth` and retries once. This retry-on-substring is deliberate —
  the comment in `publishBuzzDM` notes it exists so relays that prefix rejections with
  `msg: ` still trigger re-auth.
- DMs use `nip17.PrepareMessage` and publish **both** wraps (self copy and recipient copy) to
  the same relay, because Buzz does not implement NIP-65 / kind:10050 DM relay lists. The code
  deliberately does not use `nip17.PublishMessage` — preserve that if you touch it.
- Recipient pubkeys accept 64-char lowercase hex or an `npub`, via `buzzPubkey`.
- Everything runs under a 20s context timeout (`buzzDefaultTimeout`).

## Code style

- Standard `gofmt`; tabs, no lint config beyond `go vet`.
- Exported-style doc comments (`// funcName does ...`) on nearly every function, including
  unexported ones. Match this.
- Errors are wrapped with `%w` in `buzz.go` and newer code; older `hoot.go` code uses `%v`.
  Prefer `%w` in anything you write.
- **Import inconsistency to be aware of:** `hoot.go` still uses the deprecated `io/ioutil`
  (`ReadFile`/`WriteFile`), while `buzz.go` and `buzz_test.go` use `os`. New code should use
  `os`. Migrating `hoot.go` wholesale is a reasonable cleanup but is a separate change.
- User-facing output uses `github.com/fatih/color` (`color.Green`, `color.Cyan`, `color.Red`,
  `color.Yellow`) and interactive prompts use `github.com/manifoldco/promptui`.
- Errors are returned up to `main()`/`runBuzzCommand`, printed as `Error: %v`, then
  `os.Exit(1)`. Do not call `os.Exit` from deep helpers.

## Tests

All tests live in `buzz_test.go`, package `main`, standard library `testing` only —
no testify, no mocks, no relay fakes. Network paths are untested.

Two helpers exist and should be reused when adding tests that touch password state, since
`passwordInput` is a package-level global:

- `resetPasswordInput(t)` — clears `passwordInput` and registers cleanup
- `unsetHootPassword(t)` — unsets `HOOT_PASSWORD` and restores it after

Use `t.Setenv` for environment variables and `t.TempDir()` for files. Table-driven tests are
not currently the style here; individual named `TestXxx` functions are.

## Git and release conventions

- Default branch: `master`.
- **Conventional commits are required in practice.** `.goreleaser.yml` groups the changelog by
  regex on `feat:`, `fix:`, `docs:`, `chore:` and excludes `^docs:`, `^test:`, and merge
  commits. A commit that does not match a group is dropped from the release notes.
  Recent history: `feat: support non-interactive password input (#59)`.
- Releases are cut by pushing a `v*.*.*` tag; GoReleaser builds for linux/darwin/windows on
  amd64/arm64/386 with `CGO_ENABLED=0` and injects `main.Version`, `main.Commit`, `main.Date`
  via ldflags. Those three variables are declared at `hoot.go:31` and default to `dev`/empty —
  do not rename them without updating `.goreleaser.yml`.
- Keep `README.md` and `showHelp()` in sync when command surface changes.
