# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

- New `hoot -set key=value` (repeatable) changes individual profile fields and keeps everything else, including fields hoot doesn't know about. An empty value removes a field; the changes are printed before publishing. (`-u` still replaces the whole profile, and its help text now says so.)
- **Amber sessions are remembered.** After pairing, the login screen offers "📱 Continue as NAME (Amber)", which reconnects without a QR scan (approve on the phone if Amber asks). `x` on it forgets the saved session. The pairing is stored in `amber_session.json` (0600). It lets this computer *ask* Amber to sign; to fully revoke, also remove Hoot in Amber.
- Wallet connect (NIP-47) uses **NIP-44** encryption when the wallet advertises `nip44_v2` in its info event, and NIP-04 otherwise (older wallets).
- **Private DMs (NIP-17).** Read and send gift-wrapped messages (shown with 🔒) alongside legacy NIP-04 DMs. Messages go to the recipient's DM inbox relays (kind 10050) when they've published them. In the TUI DMs screen: `n` new message, `r` reply. From the CLI: `hoot -dm <npub> -m "text"`.
- **DMs work with Amber.** Decryption and encryption go through the remote signer (NIP-46 `nip04_*`/`nip44_*`), so no private key is needed on this computer. Only the newest messages are decrypted, since each one is a round trip to the phone.
- NIP-46 fixes: hoot subscribes for the signer's reply *before* sending a request (replies are ephemeral, so a fast signer's answer could be missed), and only accepts the response matching the request ID (concurrent requests could receive each other's results). Signed events returned by the signer are verified.
- Feed and threads: act on the selected post. **`r` reply** (NIP-10 threading: root/reply markers, everyone in the thread tagged), **`+` like** (NIP-25), **`z` zap**. Esc cancels a reply or zap and returns to the list; replying inside a thread reloads it so your reply shows up.
- **Zaps (NIP-57):** if the recipient's Lightning address supports Nostr zaps, hoot attaches a signed zap request, so the zap appears on Nostr against the post. Otherwise it's sent as a plain tip and hoot says so. Works with both local keys and Amber.
- CLI `-dms` / `-replies` show author names instead of hex prefixes when known.
- Feed: shows author **names** (from their profiles, cached for a day) instead of hex keys, in the feed, DMs and replies.
- Feed: **Following** mode: press `g` to switch between the global feed and posts from people you follow (your kind-3 contact list).
- Feed: select a post with ↑/↓ and press **Enter to open its thread** (replies and reactions); Enter on a reply opens that thread; Esc goes back. The selected post's `note1…` ID is shown so you can copy it.
- Replies lookup (TUI and `hoot -replies`) accepts `note1…`, `nevent1…` (its relay hints are queried too) and `nostr:` URIs, not just hex.
- Posts from the TUI now tag `#hashtags` like `hoot -m`. Hashtag tags are lowercased and de-duplicated, and a bare `#` no longer creates an empty tag.
- Long posts are truncated without breaking multi-byte characters.
- TUI: the feed, DMs, replies and posting no longer freeze the screen. They run in the background with a spinner, a result that arrives after you've left the screen is discarded, and a failed post keeps your draft in the composer.
- TUI: delete a saved profile from the login screen: highlight it, press `x`, confirm with `y`.
- TUI: the last-used (★) profile is highlighted when the login screen opens.
- Internal: login steps are an explicit state instead of magic cursor values (50/51/100/200); `hoot.go` and `tui/tui.go` are split into files by concern.
- Relay connections now use hoot's own client (`internal/relay`) instead of go-nostr's `Relay`/`SimplePool`. go-nostr's `Relay.close` raced with its own connection goroutine on every disconnect (in a narrow window that could nil-dereference). go-nostr is still used for event types, signing and NIP-04/19 helpers.
- Relays are queried and published to **in parallel**, so loading the feed, DMs and profiles no longer waits on each relay in turn.
- The full test suite now runs under `-race` (the relay-backed tests used to skip).
- TUI: the home menu's letter shortcuts work: **p**ost, **f**eed, **d**Ms, r**e**plies, **t**ip, **r**elays, **s**witch profile, **q**uit. Only `q` used to.
- TUI: text fields get every letter. Keys used to be matched as shortcuts first: typing `j`/`k` moved the cursor mid-form (breaking profile creation if your name or password contained them), and typing `r` in a password field **deleted the key stored with `hoot -s`**. The hidden `r` = "delete key file" binding on the login screen is gone.
- TUI: the home screen shows your full npub so you can copy it.
- CLI: new `-npub` flag prints your npub. TUI profiles don't need a password for it. Password prompts and progress spinners now go to stderr, so `NPUB=$(hoot -npub)` captures only the npub.
- Adding a profile now requires a password. The prompt said "Leave empty to skip saving", but an empty password still saved the key, encrypted with an empty password.
- README rewritten: the config directory is `hoot/` (it said `nostr-cli/`), plain `hoot` opens the TUI (it said it prints your npub), it documents Amber sign-in, tipping and every CLI flag, and warns that `-u` replaces the whole profile.
- Tipping works from the TUI: **[t] Tip someone** now takes a recipient (Lightning address, npub or hex pubkey) and an amount, and pays in the background. Previously Enter on that screen did nothing.
- Tipping now waits for the wallet's NIP-47 response (up to 60s) and reports paid (with fee and preimage), a wallet error (e.g. insufficient balance), or "unconfirmed". It used to stop after the relay accepted the request.
- Tipping refuses an invoice whose amount doesn't match what was requested, respects the recipient's LNURL min/max amounts, and reports LNURL `ERROR` reasons.
- `hoot -nwc` now rejects connection strings whose wallet pubkey or secret isn't 64-char hex (they could never pay), and accepts the `nostr+walletconnect:<pubkey>` form without `//`.
- Build: CI, tests and GoReleaser build the package (`.`) instead of only `hoot.go`, so code in other files of the main package is included.
- Tests: `TestNWCParsing` no longer overwrites the developer's real `nwc.txt`.
- Security: bumped `golang.org/x/crypto` v0.33.0 → v0.58.0 and `golang.org/x/sys` v0.37.0 → v0.49.0 (plus `term`, `text`, `net`, `sync`), clearing the known advisories govulncheck reported against those versions (GO-2025-3487, GO-2025-4116, GO-2025-4134/4135, GO-2026-5005…5033, GO-2026-6303, GO-2026-6354/6355). None were reachable from hoot's code, but they were all in the build.
- Hoot now requires **Go 1.26** (x/crypto ≥ v0.56 needs it; Go 1.24 no longer receives security fixes). `toolchain go1.26.10` pins a patched compiler for builds and releases.
- CI: new `vulncheck` job. `govulncheck ./...` (reachable code) fails the build; a module-wide scan posts its findings as a check annotation.
- Added a "Configure relays" option to the TUI login menu so relays can be reviewed, added, and removed before signing in — matters most for QR (NIP-46) pairing, which uses the configured relay set. Also wired up the relay screen's add/delete/navigate controls, which were present in the UI but not actually connected to any key handling.
- #78: the home screen now actually renders the Amber profile's NIP-05 (with ✓) and about line; the fields were fetched in #79 but never drawn. With no kind-0 profile it shows a truncated npub instead of a hex prefix.
- Feed: no longer stuck on cached posts. Once 20 events were cached, fresh posts were never shown until the cache expired. Relays are now queried first, the cache is only a fallback when they're unreachable, and posts are sorted newest first.
- DMs: query relays for the user's own conversations (`#p` + `authors`) instead of the 50 newest DMs network-wide, and decrypt sent messages with the recipient's key, so sent DMs show up again.
- Sessions: pressing Esc on the QR screen, or switching profile, now tears down the NIP-46 session. Before, a stale session could sign posts for the next login, and Esc dropped a logged-out user onto the Home menu. Ctrl+C now quits from every screen, and Esc inside the add-profile form goes back instead of quitting.
- Profiles: creating a profile in the TUI now keeps its private key, so DMs work right away. Profiles migrated from the legacy key file get their pubkey filled in on first unlock, and a stored `nsec` is decoded properly, so signing works.
- CLI: commands fall back to the last-used TUI profile when there is no legacy key file, instead of "No private key found".
- Cache: the config directory is created on first run (previously the cache failed to open on a fresh install). Expiry is stored as Unix seconds, so entries actually expire and get cleaned up, and `GetProfile` no longer fails scanning `cached_at`.
- Tests: an in-process relay (`internal/testrelay`) backs new end-to-end tests for posting, the feed, DMs, profile migration and the CLI binary. Relay-backed tests skip under `-race` because of a data race inside go-nostr v0.50's `Relay.close`; CI runs them in a separate non-race step.

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
