# Changelog

All notable changes to this project are documented here, following
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). This project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- `serve` no longer exits immediately after binding its port: the command now waits on SIGINT/SIGTERM/context cancellation instead of treating the anet server's non-blocking `Start()` as a blocking call.
- `--host` and `--port` flags actually override configuration now; previously they were bound to a viper instance nothing read.
- `TestMACValidation` no longer fails randomly: its MAC corruption could produce non-hex characters (`'A'^1='@'`, `'F'^1='G'`) and take the hex-decode path instead of MAC verification (~12% of runs).
- WASM plugins build again under Go 1.27 + TinyGo 0.42: `pkg/pinblock` test helpers moved from `test_helpers.go` (a production filename importing `testing`) to `helpers_test.go`; the `testing` import was previously compiled into every plugin.
- B2 command: `fmt.Sscanf` replaced with `strconv.ParseUint` — the `fmt` scanner machinery prevents TinyGo from linking scheduler-less WASM modules.

### Changed

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

[Unreleased]: https://github.com/andrei-cloud/go_hsm/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/andrei-cloud/go_hsm/releases/tag/v0.3.0
