# Contributing to go_hsm

Thanks for your interest in improving go_hsm! This guide gets a new contributor from clone to pull request in about ten minutes.

## Prerequisites

- [Go](https://go.dev/dl/) 1.27 or newer
- [TinyGo](https://tinygo.org/getting-started/install/) 0.42 or newer (only needed to build WASM plugins; requires LLVM 22)
- [golangci-lint](https://golangci-lint.run/welcome/install/) v2 (optional, for linting)
- GNU make

## First build

```bash
git clone https://github.com/andrei-cloud/go_hsm.git
cd go_hsm
make build       # bin/go_hsm — the server and CLI
make plugins     # plugins/*.wasm — the HSM command plugins
make test        # full test suite
```

Quick manual check:

```bash
make run         # server on :1500 with debug logging
# in a second shell:
echo -ne 'NC' | ./script/send_with_length.sh 127.0.0.1 1500
```

## Project layout

- `cmd/go_hsm` — server + CLI entry point; `cmd/plugingen` — plugin wrapper generator
- `internal/commands/cli` — cobra command tree
- `internal/hsm/logic` — one file per HSM command: the pure logic, unit-tested natively
- `internal/commands/plugins/<CODE>` — the TinyGo WASM wrapper stub per command
- `internal/plugins`, `internal/server` — plugin manager (pooling, hot-reload) and the TCP server
- `pkg/...` — importable library packages (key blocks, PIN blocks, crypto utilities)
- `script/` — framing/test helpers; `plugins/` — build output (not tracked)

## Making a change

1. Create a branch from `main`.
2. Make your change. For a new HSM command, use the scaffolder:
   ```bash
   ./bin/go_hsm plugin create FO --desc "Format Output" --version 1.0.0 --author "You"
   make plugins CMD=FO && make test
   ```
3. Verify before pushing:
   ```bash
   make test
   go build ./cmd/...
   golangci-lint run ./...     # config: .golangci.yml (golangci-lint v2)
   ```
4. Push and open a pull request against `main`. Describe *what* changed and *why*; link an issue when there is one.

## Conventions

- Follow the style enforced by `.golangci.yml`; run `golangci-lint fmt ./...` for formatting.
- Exported identifiers carry doc comments starting with the identifier name.
- Errors are wrapped with `fmt.Errorf("...: %w", err)`; command results use the shared `internal/errorcodes` catalogue (never invent ad-hoc error codes on the wire).
- WASM plugins are built with `-scheduler=none`: guest code must not start goroutines or write to `os.Stdout`/`os.Stderr`; use the host logging functions (`logInfo`/`logDebug`/`logError`) and the host CSPRNG. Keep `testing` imports out of any non-`_test.go` file in guest-linked packages.
- Tests: table-driven with named subtests; new behavior ships with tests.

## Reporting issues

Include: go_hsm version (`./bin/go_hsm --version`), Go/TinyGo versions, the exact request sent (hex), expected vs. observed response, and the full command you ran.

## License

By contributing, you agree that your contributions are licensed under the project's [MIT license](LICENSE).
