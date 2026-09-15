# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-09-14

Eight PRs since v0.2.0, all bug fixes around the NIP-46 QR login flow and a broader codebase review.

### NIP-46 QR login (the user's main complaint this session)

- PRs #65, #66: TUI never reached a visible QR code. The render path had a flag-stuck race AND was inflating each module to 6 columns (passing 6-byte ANSI escape sequences as half-block characters). QR is now ~47 visual columns, scannable.
- PR #67: "Still showing Generating" with no progress. Stale `m.message = "Generating QR code..."` survived across the QR render AND there was no live spinner. Now shows a bubbletea spinner frame and clears the stale banner.
- PR #68: The title, QR, "Waiting for connection..." footer, and "Press Esc" footer were at four different indents. The QR group is now right-padded to a uniform width and the whole block is centered as one rectangle.
- PR #69: Connect to all configured relays instead of just the first. NIP-46 spec allows advertising multiple relays and lets the signer pick; hoot was picking `relays[0]` so if that single relay was down, the user got a websocket error.
- PR #70: Subscribe before showing the QR (so the connect event isn't missed during a 10-15s dial delay) and retry polling in a `tea.Tick` loop in the TUI.

### Codebase review fixes (PR #71, 11 bugs)

- `eventCache` shadowed by `:=` in `main()` — caching was silently broken for the entire process
- `getDMs()` called `nip04.Decrypt` with raw private key bytes instead of the computed shared secret — DMs always empty
- Text input blocked at cursor states 51/200 — couldn't type nsec or unlock existing profiles
- NIP-89 handler registration used kind 1984 (reports) instead of 31990
- NIP-89 'a' tag format was reversed (`pubkey:d:kind` instead of `kind:pubkey:d`)
- Missing bounds check on `tag[1]` — potential panic on malformed relay events
- DMs/Replies `withLoading` errors silently discarded
- `defer cancel()` inside relay loop leaked N-1 contexts per publish
- Home screen cursor had no upper bound — could scroll past menu items
- NIP-46 `publishToAllRelays` returned error on first relay failure even if others succeeded
- `publishPostTUI` ignored `GetPublicKey` and `Sign` errors — could publish malformed posts

### Infrastructure

- CI: skip `TestStoreAndLoadKey` when no interactive TTY (this runs in sandboxes)
- Version variables are now ldflags-injectable; `hoot -version` shows commit hash and build date

## [0.2.0] - 2026-09-11

Bug fixes from PRs #61-#64:

- Dedupe `defaultRelays` slice at process start (the `wss://nostr.wine` duplicate caused double-publish and double-counted "success")
- `generateProfileID` entropy-failure fallback uses nanosecond timestamp, not a hex-of-zero-buffer collision
- NWC payment honesty: 30s timeout on tip requests, checked `event.Sign()` error, honest post-publish message
- `log.Fatalf` replaced with `log.Printf` + `os.Exit(1)` so defers (notably `eventCache.Close`) run on publish failure
- Untrack 26 MB of build artifacts from git history (`.gitignore` covers Go binaries, test caches, coverage, IDE scratch)

[Unreleased]: https://github.com/oth-body/hoot/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/oth-body/hoot/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/oth-body/hoot/compare/v0.1.0...v0.2.0
