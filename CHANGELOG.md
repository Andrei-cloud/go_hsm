# Changelog

All notable changes to this project are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.4.0] - 2026-11-14

### Added

- M6 (generate MAC) and M8 (verify MAC) commands: ISO/IEC 9797-1 algorithm 1 (TDEA on every block) and algorithm 3 (retail MAC), 8- or 16-digit MACs, binary or hex input, padding methods 0-2, under a TAK (003) or ZAK (008). Mode 0 (a message in a single block) only. M8 answers `M901` when the MAC does not hold, and compares the MAC in constant time.
- A6 (import a key under ZMK) and A8 (export a key under ZMK) commands for the ANSI X9.17 ECB forms: `Z` (or untagged) single, `X` double and `Y` triple length. Both return the key's 6-digit check value; A6 answers `01` with the key when the imported key has a parity error. The Thales variant forms `U`/`T` under a ZMK answer 26.
- A6 and A8 also carry keys as ANSI X9 TR-31 key blocks. A request whose key-under-ZMK starts with `R` is opened under the ZMK as a version-B block, and its key usage, algorithm and mode of use must fit the requested key type — a ZAK may be taken in as `M0`, `M1` or `M3`, a ZPK only as `P0`; A8 seals the key with no further export and key version `00`. Because the block is MAC-authenticated, a tampered or wrongly-keyed block answers `A4` rather than yielding a key.
- `RandomBytes` host function for WASM plugins: plain random bytes from the host CSPRNG with no key-length rule and no DES parity applied, so padding and nonces get uniform data. Capped at 4096 bytes per call, and failing closed rather than substituting predictable bytes.
- Error codes 03 (invalid input format flag), 06 (invalid message length) and 09 (invalid padding method) in the shared catalogue.

### Fixed

- WASM plugins ran none of their package initialisers. Modules were instantiated with no start function, and TinyGo only exports `_initialize` for a `c-shared` build, so `init()` bodies were skipped entirely. Consequence: `pkg/pinblock`'s `Rand` stayed nil inside every plugin — the non-nil default is behind `//go:build !wasm` and the assignment lives in a `logic` `init()` — so encoding a PAN-based PIN block (ISO1, Visa New, …) panicked on `io.ReadFull(nil, …)`. Plugins now build with `-buildmode=c-shared` and run `_initialize` as their start function.
- PIN block padding was not random. `GetRandomHexDigit` and `GetRandomHexDigitAF` ask for one byte, but the reader went through `GenerateRandomKey`, which rejects every length outside 8, 16 or 24 bytes; the error was swallowed and a literal `"0"` returned. Even at a valid length the result carried DES parity correction, which makes the bytes structurally non-uniform for padding. Both now read a dedicated host CSPRNG call.
- `--plugin-path` was silently ignored: the flag is bound to the global `viper` instance, while `config` reads its own `viper.New()`, so `runServe` always used the configured path. The flag now takes precedence, the same way `--host` and `--port` already did.
- `serve` no longer exits immediately after binding its port: the command now waits on SIGINT/SIGTERM/context cancellation instead of treating the anet server's non-blocking `Start()` as a blocking call.
- `--host` and `--port` flags actually override configuration now; previously they were bound to a viper instance nothing read.
- `TestMACValidation` no longer fails randomly: its MAC corruption could produce non-hex characters (`'A'^1='@'`, `'F'^1='G'`) and take the hex-decode path instead of MAC verification (~12% of runs).
- WASM plugins build again under Go 1.27 + TinyGo 0.42: `pkg/pinblock` test helpers moved from `test_helpers.go` (a production filename importing `testing`) to `helpers_test.go`; the `testing` import was previously compiled into every plugin.
- B2 command: `fmt.Sscanf` replaced with `strconv.ParseUint` — the `fmt` scanner machinery prevents TinyGo from linking scheduler-less WASM modules.

### Changed

- Documentation rebuilt: `README.md` rewritten, `CONTRIBUTING.md`, this `CHANGELOG.md` and `llms.txt` added, and godoc filled in across `cmd/`, `internal/` and `pkg/`.
- Plugins are built with `tinygo build -target=wasi -buildmode=c-shared`, which is what makes `_initialize` (and therefore package initialisers) present in the module.
- Adds `github.com/moov-io/tr31` for TR-31 key blocks. The module is temporarily `replace`d with a fork whose changes make the library's random source injectable and drop the goroutine from `Blocks.Iter` so the package links under scheduler-less TinyGo; tracked in #16 for upstreaming and removal of the directive.
- Go directive raised to 1.27.1; all dependencies updated (zerolog 1.35.1, cobra 1.10.2, testify 1.12.1, wazero 1.12.0, mapstructure v2.5.0, plus indirect updates).
- `.golangci.yml` migrated to golangci-lint v2 format (the v1 config was rejected outright, so linting never ran); unconfigured/contrarian linters disabled with reasons.
- `pkg/pinblock` padding randomness now comes from an injectable `Rand` source; WASM guests wire the host CSPRNG, since TinyGo's wasip1 `crypto/rand` file fallback requires a goroutine scheduler.

## [0.3.0] - 2026-08-15

### Added

- Bounded plugin instance pooling with context-aware lifecycle: configurable pool limits, starvation timeouts, and immediate WASM linear-memory reclamation on release.
- `LMKProvider` proxy with atomic hot-swap access.
- Benchmark suites for command paths and an LMK key-derivation proxy; `make bench` and `make bench-load` targets for component benchmarks and end-to-end TCP load tests.
- Key block parsing/validation and integration tests for Thales `S` and TR-31 `R` formats (added in 0.2.x line, hardened through test refactors).

### Changed

- Plugin hot-reload (`SIGHUP`) rebuilt on top of the new pooling: zero-downtime reload swaps the plugin set atomically.
- CLI plugin generator updated for the new lifecycle.

## 0.2.0 — 2025-06-23 (untracked pre-release line)

### Added

- Thales variant-LMK key generation, import and check CLI commands (`keys generate|import|check`) with parity validation and interactive TUI for key block headers.
- Key block support for Thales `S` format key blocks.

[Unreleased]: https://github.com/andrei-cloud/go_hsm/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/andrei-cloud/go_hsm/releases/tag/v0.4.0
[0.3.0]: https://github.com/andrei-cloud/go_hsm/releases/tag/v0.3.0
