# go_hsm

[![Go Reference](https://pkg.go.dev/badge/github.com/andrei-cloud/go_hsm.svg)](https://pkg.go.dev/github.com/andrei-cloud/go_hsm)
[![Go Version](https://img.shields.io/github/go-mod/go-version/andrei-cloud/go_hsm)](https://go.dev/)
[![Go Report Card](https://goreportcard.com/badge/github.com/andrei-cloud/go_hsm)](https://goreportcard.com/report/github.com/andrei-cloud/go_hsm)
[![License](https://img.shields.io/github/license/andrei-cloud/go_hsm)](./LICENSE)

A Hardware Security Module (HSM) emulator written in Go, compatible with Thales/Racal HSM protocols. Each HSM command runs as an isolated WASM plugin, so new commands can be added — or reloaded at runtime — without touching the server core.

Built for two audiences: developers who need a realistic, scriptable HSM in tests and CI, and anyone who wants to study how payment-cryptographic HSMs work end to end.

## Demo

Start the server, send one framed request, get an HSM response:

```console
$ ./bin/go_hsm serve --port 1500 &
$ echo -ne 'A00001U' | ./script/send_with_length.sh 127.0.0.1 1500
request 1/1:
00000000  00 0b 00 00 03 7f 41 30  30 30 30 31 55           |......A00001U|
00000000  00 2f 00 00 03 7f 41 31  30 30 55 33 35 42 36 45  |./....A100U35B6E|
...
```

Request `A00001U` asks the HSM to generate a key (type `000`, mode `1`, modifier `U`); the response `A100U<key>` carries the generated key material.

## Getting Started

### Prerequisites

| Tool | Version | Needed for |
|------|---------|------------|
| Go | 1.27+ | building the server, CLI, tests |
| TinyGo | 0.42+ (LLVM 22) | building WASM plugins only |
| GNU make | any | build automation |

### Build and run

```bash
git clone https://github.com/andrei-cloud/go_hsm.git
cd go_hsm
make build          # builds bin/go_hsm (CGO_ENABLED=0, static)
make plugins        # builds plugins/*.wasm with TinyGo
./bin/go_hsm serve --port 1500
```

Then verify in another shell:

```bash
echo -ne 'NC' | ./script/send_with_length.sh 127.0.0.1 1500
```

The server answers `ND00000000000000007000-E000` — diagnostics with the firmware version.

## Configuration

Configuration is layered; the first source that provides a value wins:

1. CLI flags (only when explicitly set, e.g. `--host`, `--port`)
2. Environment variables (`GOHSM_SERVER_PORT`, `GOHSM_LOG_LEVEL`, …)
3. Config file: `./config.yaml`, `$HOME/.go_hsm/config.yaml`, or `/etc/go_hsm/config.yaml` (the first found; auto-created in `$HOME/.go_hsm` on first run)
4. Built-in defaults

<details>
<summary>Default configuration file</summary>

```yaml
server:
  host: localhost
  port: 1500
  maxconns: 1000
  maxconcurrenthandlers: 10000
  readtimeout: 30s
  writetimeout: 30s
  idletimeout: 0s
  keepaliveinterval: 30s
  shutdowntimeout: 5s

plugin:
  path: plugins
  executiontimeout: 2s
  poolsize: 10

log:
  level: info
  format: human
```
</details>

### Server lifecycle

```bash
./bin/go_hsm serve --host 0.0.0.0 --port 1500 --log-level debug
```

| Signal | Effect |
|--------|--------|
| `SIGHUP` | Hot-reload all plugins from disk — zero downtime, in-flight requests unaffected |
| `SIGINT` / `SIGTERM` | Graceful shutdown (drains in-flight connections up to `shutdowntimeout`) |

## Implemented HSM Commands

Implemented as WASM plugins, with more extensible via the plugin system:

| Command | Description |
|---------|-------------|
| A0 | Generate a random key |
| B2 | Echo test command |
| BU | Generate Key Check Value (KCV) |
| CA | Translate a PIN from TPK to ZPK |
| CW | Generate a Card Verification Code (CVV) |
| CY | Verify a Card Verification Code/Value |
| DC | Verify a Terminal PIN using the ABA PVV method |
| EC | Verify an Interchange PIN using the ABA PVV |
| FA | Translate a ZPK from ZMK to LMK |
| HC | Generate a TMK, TPK or PVK variant LMK key |
| NC | Network diagnostics (firmware version) |
| KQ | ARQC verification and/or ARPC generation |

## Wire Protocol

Messages use the Thales/Racal framing that the `script/` helpers generate automatically:

- 2-byte big-endian length prefix (payload length)
- 4-byte task identifier (incremental counter for message tracking)
- Payload: two-character HSM command code + command data

Responses increment the command code's second letter (`A0` → `A1` means success; `A0` → `A8`+ style codes signal errors, e.g. `Err76` function not permitted).

### Testing with the bundled scripts

```bash
# Simple commands — send raw stdin with framing:
echo -ne 'A00001U' | ./script/send_with_length.sh 127.0.0.1 1500

# Commands with binary fields — parse_command.sh converts fields, then sends:
./script/parse_command.sh "<command-string>" 127.0.0.1 1500
```

`parse_command.sh` field formats:

| Syntax | Meaning |
|--------|---------|
| `8B:1111111111111100` | 8-byte binary from hex |
| `4B:52BF4585` | 4-byte binary from hex |
| `2B:005E` | 2-byte binary from hex |
| `2H:74` | 2 hex chars representing decimal 74 |
| `B:0000000123...;` | variable-length binary until `;` |
| `\|` | field delimiter |
| unprefixed | passed as-is |

Example — KQ (ARQC verify / ARPC generate):

```bash
./script/parse_command.sh "KQ00U7475636CC30B93B493CF5EA53799EBCC|8B:1111111111111100|2B:005E|4B:52BF4585|2H:37|B:0000000123000000000000000784800004800008402505220052BF45851800005E06011203;|8B:076C5766F738E9A6" 127.0.0.1 1500
```

## CLI Usage

### Key generation

```bash
./bin/go_hsm keys generate --type 000 --scheme U
```

```
Key Type: Name: ZMK, Code: 000, LMKPairIndex: 2, VariantID: 0
Key Scheme: U
Encrypted Key: UC734ACEC91D7DBBBB2EA63EAF3F6E4DA
KCV: E5EEC3
```

Flags: `--type` key type code, `--scheme` LMK scheme (`X`/`U`/`T`, default `U`), `--clear` print the clear key (test/dev only), `--pci` enable PCI compliance mode.

| Key type | Name | Description |
|----------|------|-------------|
| 000 | ZMK | Zone Master Key |
| 001 | ZPK | Zone PIN Key |
| 002 | PVK/Generic | PIN Verification Key |
| 003 | TMK | Terminal Master Key |
| 004 | TPK | Terminal PIN Key |
| 009 | ZMAC | Zone MAC Key |

| Scheme | Description | Key length |
|--------|-------------|------------|
| X | Single-length DES | 8 bytes (16 hex chars) |
| U | Double-length 3DES | 16 bytes (32 hex chars) |
| T | Triple-length 3DES | 24 bytes (48 hex chars) |

### Key import

```bash
./bin/go_hsm keys import --key DF40519B0775B3B9 --type 001 --scheme X
```

Flags: `--key` clear key hex (16/32/48 hex chars), `--type`, `--scheme` (auto-detected from key length when omitted), `--force-parity` fix invalid DES parity (otherwise the command fails), `--pci`.

With `--lmk-id 01` the import opens an interactive TUI (Bubble Tea) for composing the key block header: field navigation with Tab/arrows, radio choices for usage/algorithm/mode/exportability, direct numeric entry for key version, live validation.

### Key block inspection

```bash
./bin/go_hsm keys check --keyblock S1009651TB00S00003F7FA0520BABA0C6A99E88E82D48040FA4826CA256996A532A1E0059A90B472E477C5926420CA4C7
```

Prints a field-by-field breakdown of Thales `S`/`K` and TR-31 `R` key block headers (version, length, usage, algorithm, mode of use, exportability, optional blocks, LMK ID), the encrypted key data, and the MAC section. Add `--lmk-index` to validate the MAC against a configured LMK.

### PIN blocks

```bash
./bin/go_hsm pinblock --pin 1234 --pan 4111111111111111 --format 01
```

### Plugin management

```bash
./bin/go_hsm plugin list   # table of loaded plugins: code, version, description, author
./bin/go_hsm plugin create FO --desc "Format Output" --version 1.0.0 --author "You"
```

## Plugin System

- Each HSM command is a separate TinyGo-compiled WASM module for isolation and extensibility.
- Host↔guest calls use direct `api.GoModuleFunc` host functions — no Go reflection on the hot path.
- Plugin instances run from a bounded pool with configurable limits and starvation timeouts; released instances return their WASM linear memory immediately.
- On `SIGHUP` the server builds a fresh plugin set from disk and swaps it atomically — reload with zero dropped requests.
- Guest randomness is injected from the host CSPRNG (`pinblock.Rand`), since a `-scheduler=none` WASM module cannot use `crypto/rand`'s file fallback on wasip1.

### Adding a command

```bash
./bin/go_hsm plugin create FO --desc "Format Output" --version 1.0.0 --author "You"
```

This scaffolds `internal/hsm/logic/FO.go` + test, a plugin stub under `internal/commands/plugins/FO/`, then:

```bash
make plugins CMD=FO   # generate wrapper + build FO.wasm
make test             # run the Go tests
```

`FO.wasm` lands in `plugins/` and is loaded by the server (or hot-reloaded with `SIGHUP`).

## Performance

Measured on Apple Silicon (M1 Pro), loopback TCP, Go 1.27 / TinyGo 0.42 / anet v0.3.0, August 2026. Re-run with `make bench` and `make bench-load`.

### End-to-end TCP load test (throughput by worker count)

| Workers | Throughput | Total requests | P50 | P90 | P99 |
|---------|------------|----------------|-----|-----|-----|
| 1 | 13,442 req/s | 1,000 | 68.2 µs | 104.7 µs | 150.7 µs |
| 10 | 66,789 req/s | 10,000 | 137.6 µs | 217.9 µs | 345.4 µs |
| 50 | 87,299 req/s | 50,000 | 505.3 µs | 988.9 µs | 1.61 ms |
| 100 | 88,449 req/s | 100,000 | 1.03 ms | 1.95 ms | 2.98 ms |

### Cryptographic core benchmarks

| Operation | Latency | Throughput | Allocations |
|-----------|---------|------------|-------------|
| ExecuteB2 (LMK query/echo) | 550 ns/op | 1.82 M ops/s | 11 allocs (232 B) |
| ExecuteKQ (keyblock derive/verify) | 554 ns/op | 1.80 M ops/s | 8 allocs (488 B) |
| ExecuteNC (firmware diagnostics) | 889 ns/op | 1.13 M ops/s | 20 allocs (776 B) |
| ExecuteCW (CVV generation) | 5,377 ns/op | 186 k ops/s | 82 allocs (2.5 KB) |
| ExecuteA0 (key gen, plain) | 8,796 ns/op | 113 k ops/s | 45 allocs (2.2 KB) |
| ExecuteA0 (key gen, ZMK-wrapped) | 13,056 ns/op | 76.6 k ops/s | 63 allocs (3.5 KB) |

Key optimizations behind these numbers: lock-free request-ID generation (zero syscalls on the hot path), reflection-free WASM host functions, bounded instance pooling with immediate linear-memory reclamation, zerolog level guards that skip formatting entirely when disabled, and bucketed buffer pooling that zeroes reused slices.

## Project Structure

```
cmd/
  go_hsm/             # server + CLI entry point
  plugingen/          # WASM plugin wrapper generator
internal/
  commands/cli/       # cobra commands: serve, keys, pinblock, plugin
  commands/plugins/   # per-command plugin stubs (A0..KQ)
  config/             # viper configuration (flags > env > file > defaults)
  errorcodes/         # HSM error-code catalogue
  hsm/                # core HSM service + logic/ command implementations
  pinblock/           # PIN block helpers
  plugins/            # plugin manager: loading, pooling, hot-reload
  server/             # TCP server (anet) + request routing
pkg/                  # importable packages: crypto, cryptoutils, hsmplugin,
                      # keyblocklmk (Thales S / TR-31 key blocks), pinblock,
                      # variantlmk (variant-LMK protection), common (logging)
script/               # request framing/testing helpers
plugins/              # built WASM plugins (build output, not tracked)
```

## Development Workflow

```bash
make help        # list all targets
make build       # build bin/go_hsm
make plugins     # build all WASM plugins (CMD=NAME for a single one)
make run         # build and run the server on :1500 with debug logging
make test        # run all Go tests
make bench       # component + cryptographic benchmarks
make bench-load  # end-to-end TCP throughput/latency load tests
make clean       # remove build outputs
```

Linting uses golangci-lint v2 (`default: all` configuration, `.golangci.yml`):

```bash
golangci-lint run ./...
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for the full contributor guide.

## Security Notes

- Key generation uses `crypto/rand`; DES key parity and KCV are validated on import.
- Plugins execute inside WASM sandboxes with host-mediated access only.
- Key material is zeroed on release from the plugin and buffer pools.
- `--clear` and debug logging can expose clear keys: development only.

## License

MIT — see [LICENSE](LICENSE).

## Author

Created and maintained by Andrey Babikov. Please reference the original author in derivative works or publications.
