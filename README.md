# go_hsm

A Go-based Hardware Security Module (HSM) implementation compatible with Thales/Racal protocols, featuring a WASM-based plugin architecture for command extensibility and hot-reload.

> **Unleash your creativity: Easily add new HSM commands as plugins—contribute your own or extend the system for your needs!**

---

## Features

- Memory-efficient buffer pooling for high-throughput environments.
- WASM-based plugin system for secure, isolated, and extensible command implementation.
- Hot-reload support: reload plugins at runtime with SIGHUP, no server restart required.
- CLI for server management, plugin management, and cryptographic utilities.
- Compatible with Thales/Racal HSM protocols and standard PIN block formats.
- Table-driven tests and example-driven documentation for all exported APIs.
- Structured logging and error handling for robust production and development use.

---

## Quick Start

1. Clone and build:
   ```bash
   git clone https://github.com/andrei-cloud/go_hsm.git
   cd go_hsm
   make build
   ```
2. Build WASM plugins:
   ```bash
   make plugins
   ```
3. Start the HSM server:
   ```bash
   ./bin/go_hsm serve --port 1500
   ```
4. Generate a PIN block:
   ```bash
   ./bin/go_hsm pinblock --pin 1234 --pan 4111111111111111 --format 01
   ```

---

## Project Structure

```
├── cmd/
│   ├── go_hsm/           # Main HSM server and CLI
│   │   ├── main.go      # Entry point
│   │   └── cmd/         # CLI commands (serve, plugin, pinblock, etc.)
│   └── plugingen/       # Plugin generator
├── internal/
│   ├── hsm/            # Core HSM logic
│   │   └── logic/      # Command implementations
│   ├── plugins/        # Plugin system
│   └── server/         # TCP server
├── pkg/                # Public packages (crypto, pinblock, etc.)
├── plugins/            # Compiled WASM plugins
├── Makefile            # Build and test automation
├── README.md           # Project documentation
├── LICENSE             # Open source license (MIT)
```

---

## Plugin System Overview

### Architecture
- Each HSM command is implemented as a separate WASM plugin for isolation and extensibility.
- Plugins are loaded at server startup and can be hot-reloaded at runtime (SIGHUP signal).
- The server delegates command execution to the appropriate plugin via the plugin manager.
- Plugin metadata (command, version, description, author) is displayed via CLI and logs.

### Plugin Management CLI

- **List plugins:**
  ```bash
  ./bin/go_hsm plugin list
  ```
  Outputs a table of all loaded plugins with their command code, version, description, and author.

- **Create a new plugin:**
  ```bash
  ./bin/go_hsm plugin create <NAME> --desc "Description" --version 1.0.0 --author "Author Name"
  ```
  This will:
  1. Create a logic file in `internal/hsm/logic/`.
  2. Create a test file for the command logic.
  3. Create a plugin stub in `internal/commands/plugins/<NAME>/gen.go`.
  4. Run `make gen` to generate the WASM wrapper.
  5. Build the plugin with `make plugins CMD=<NAME>`.

- **Plugin build and generation:**
  - `make gen` runs `go generate` for all plugin stubs, creating WASM wrappers.
  - `make plugins` builds all plugins using TinyGo, outputting `.wasm` files to the `plugins/` directory.
  - To build a single plugin: `make plugins CMD=FO` (for command FO).

### Hot-Reload Plugins
- The server supports hot-reloading plugins at runtime by sending SIGHUP:
  ```bash
  kill -SIGHUP <server-pid>
  ```
- The plugin manager will reload all plugins from the plugin directory, and the server will use the new set immediately.

---

## Server Operation

- The server is started with the `serve` command:
  ```bash
  ./bin/go_hsm serve --port 1500 --plugin-dir=./plugins
  ```
- On startup, the server loads all plugins from the specified directory and logs their metadata.
- The server listens for TCP connections and delegates command processing to the appropriate plugin.
- On SIGHUP, the server reloads plugins without restarting.
- Graceful shutdown is supported via SIGINT/SIGTERM.

---

## Development Workflow

### Adding a New Command Plugin

1. **Create logic and test files:**
   - Logic: `internal/hsm/logic/FO.go`
   - Test:  `internal/hsm/logic/FO_test.go`
2. **Create plugin stub:**
   - `internal/commands/plugins/FO/gen.go` with a `go:generate` directive for `plugingen`.
3. **Generate wrapper and build plugin:**
   - Run `make gen` to generate WASM wrapper.
   - Run `make plugins CMD=FO` to build the plugin.
4. **Test:**
   - Run `make test` to execute all tests.
5. **Deploy:**
   - The resulting `FO.wasm` will be in the `plugins/` directory and loaded by the server.

### Example: Creating a Plugin

```bash
./bin/go_hsm plugin create FO --desc "Format Output" --version 1.0.0 --author "Alice"
```

---

## Makefile Targets

- `make build`      - Build the HSM CLI/server binary.
- `make plugins`    - Build all WASM plugins (or a single one with `CMD=NAME`).
- `make gen`        - Generate plugin wrappers for all commands.
- `make test`       - Run all Go tests.
- `make clean`      - Remove built binaries and plugins.
- `make cli`        - Build the CLI binary.
- `make install`    - Install CLI to `$GOPATH/bin`.

---

## Security Features

- Secure random key generation and cryptographic operations.
- WASM-based isolation for plugin execution.
- Secure memory handling and LMK protection.
- Command-level authorization and audit logging.

---

## Contributing

1. Fork the repository.
2. Implement new command logic and tests.
3. Add a plugin stub and generate the wrapper.
4. Build and test the plugin.
5. Submit a pull request with a description of your changes.

---

## License

This project is licensed under the MIT License for open source development and study purposes. See the LICENSE file for details.

---

## Author & Attribution

Created and maintained by Andrey Babikov. Please reference the original author in derivative works or publications.