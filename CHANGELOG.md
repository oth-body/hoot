# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- NIP-46 QR login: render QR code correctly in half-block Unicode glyphs (#65, #66)
- NIP-46 QR login: show live spinner while waiting, clear stale "Generating" banner (#67)
- NIP-46 QR login: center title, QR, and footers as one cohesive block (#68)
- NIP-46: dial all configured relays instead of only the first; retry on failure (#69, #70)
- Event cache shadowed by := — caching was silently broken (#71)
- DM decryption used raw private key instead of shared secret — DMs always empty (#71)
- Text input blocked at cursor states 51/200 — couldn't type nsec or unlock profiles (#71)
- NIP-89 handler registration used wrong kind (1984 instead of 31990) (#71)
- NIP-89 'a' tag format reversed (was pubkey:d:kind, now kind:pubkey:d) (#71)
- Missing bounds check on tag elements — potential panic on malformed events (#71)
- DMs/Replies withLoading errors silently discarded (#71)
- Context leak from defer cancel() inside relay loop (#71)
- Home screen cursor unbounded — could scroll past menu items (#71)
- NIP-46 publishToAllRelays failed on first relay error even if others succeeded (#71)
- publishPostTUI ignored GetPublicKey/Sign errors (#71)
- CI: skip TestStoreAndLoadKey when no interactive TTY available (#65)

### Changed
- Build-time version injection via ldflags (version, commit, date)
- `hoot -version` now shows commit hash and build date

## [0.0.4] - 2024-12-01

### Added
- Initial TUI with Bubble Tea
- NIP-46 remote signer support (Amber QR scan)
- Multi-profile management
- NWC tipping via Lightning
- NIP-89 app handler registration
- Direct messages view
- Replies/reactions view
- Relay management
- Event caching with SQLite

[Unreleased]: https://github.com/oth-body/hoot/compare/v0.0.4...HEAD
[0.0.4]: https://github.com/oth-body/hoot/releases/tag/v0.0.4
