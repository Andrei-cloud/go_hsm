# go_hsm

A Go-based Hardware Security Module (HSM) implementation compatible with Thales/Racal protocols, featuring WASM-based plugin architecture for command extensibility ### Quick Start

1. Clone and build:
```bash
git clone https://github.com/andrei-cloud/go_hsm.git
cd go_hsm
make all
```

2. Build WASM plugins:
```bash
make plugins
```

3. Start the HSM server:
```bash
./bin/go_hsm serve --port 1500 --lmk $(cat lmk.key)
```

4. Generate a PIN block:
```bash
./bin/go_hsm pinblock --pin 1234 --pan 4111111111111111 --format 01
```

## Development Guide

### Adding a New Command

1. Create command logic in `internal/hsm/logic/`
2. Generate WASM wrapper using `plugingen`
3. Implement the command interface
4. Build and test the WASM plugin
5. Deploy to the plugins directory

### Testing

```bash
# Run all tests
make test

# Test specific command
make test-cmd CMD=A0

# Run integration tests
make test-integration
```

## License

This project is licensed under the MIT License. See the LICENSE file for details.raphic operations.

## Overview

The `go_hsm` project provides a modern, secure, and extensible HSM implementation with the following key features:

- **Plugin Architecture**: Commands are implemented as WebAssembly (WASM) modules, providing isolation and flexibility
- **Cryptographic Operations**: Secure implementation of encryption, key generation, and PIN block operations
- **Hot Reload Support**: Dynamic command loading without server restart
- **CLI Interface**: Comprehensive command-line interface for server control and utilities
- **Standard Compliance**: Implementation of ISO 9564-1 and various PIN block formats

Table of Contents
-----------------
- [Introduction](#introduction)
- [Features](#features)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Clone Repository](#clone-repository)
  - [Build WASM Plugins](#build-wasm-plugins)
  - [Generate Plugin Wrappers](#generate-plugin-wrappers)
  - [Build the Server](#build-the-server)
  - [Build the CLI](#build-the-cli)
  - [Install the CLI](#install-the-cli)
  - [Run the Server](#run-the-server)
  - [Testing](#testing)
  - [Cleaning](#cleaning)
- [CLI Usage](#cli-usage)
  - [HSM Server](#hsm-server)
  - [PIN Block Generation](#pin-block-generation)
- [Writing a New Command](#writing-a-new-command)
  - [1. Implement Business Logic](#1-implement-business-logic)
  - [2. Add go:generate Stub](#2-add-generate-stub)
  - [3. Generate Wrapper](#3-generate-wrapper)
  - [4. Build the Plugin](#4-build-the-plugin)
- [Contributing](#contributing)
- [License](#license)

## Core Components

### 1. HSM Core (internal/hsm)
- Secure implementation of Local Master Key (LMK) operations
- Support for various key lengths and formats
- Cryptographically secure random key generation
- PIN block format conversions (ISO, ANSI, Visa, etc.)

### 2. Plugin System (internal/plugins)
- WASM-based command isolation
- Hot-reload capability via `SIGHUP`
- Secure memory management for cryptographic operations
- Dynamic command registration and execution

### 3. Command Implementation (internal/hsm/logic)
- Clean separation of business logic per command
- Standardized error handling
- Comprehensive logging and debugging support
- Testable command implementations

### 4. Cryptographic Utilities (pkg/cryptoutils)
- Secure random key generation
- Key Check Value (KCV) calculation
- Various cryptographic operations
- PIN block format implementations

### 5. CLI Interface
- Server management commands
- PIN block generation utilities
- Key management operations
- Plugin management tools

## Supported Commands

The HSM supports various commands through its plugin system:

- **A0**: Random key generation with configurable key formats
- **BU**: PIN block translation between formats
- **DC**: PIN verification and change operations
- **EC**: PIN encryption operations
- **NC**: Network control and status commands

Each command is implemented as a separate WASM module, providing:
- Isolation of command logic
- Independent testing
- Easy deployment and updates
- Secure memory management

## Project Structure

```go
├── cmd/
│   ├── go_hsm/           # Main HSM server and CLI
│   │   ├── main.go      # Entry point
│   │   └── cmd/         # CLI commands
│   │       ├── root.go  # Base command
│   │       ├── serve.go # HSM server
│   │       └── pinblock.go # PIN utilities
│   └── plugingen/       # Plugin generator
├── internal/
│   ├── hsm/            # Core HSM functionality
│   │   └── logic/      # Command implementations
│   ├── plugins/        # Plugin system
│   └── server/         # Network server
│   ├── A0
│   ├── BU
│   ├── DC
│   ├── EC
│   ├── NC
├── internal             # Internal server and HSM implementations
│   ├── cli              # CLI utilities (formatting, operations)
│   ├── errorcodes       # HSM error codes
│   ├── hsm              # HSM core and command logic
│   │   └── logic        # Command implementations
│   ├── logging          # Structured logging
│   ├── plugins          # Plugin manager
│   └── server           # Server implementation
├── pkg                  # Public packages
│   ├── cryptoutils      # Cryptographic utilities
│   ├── hsmplugin        # WASM plugin helpers
│   ├── pinblock         # PIN block algorithms and formats
│   └── variantlmk       # LMK handling utilities
├── Makefile
├── README.md
├── go.mod
└── go.sum
```

## Getting Started

## Security Features

1. **Cryptographic Operations**
   - Secure random key generation using crypto/rand
   - Triple DES encryption for key protection
   - Key Check Value (KCV) verification

2. **Memory Protection**
   - WASM-based isolation of command execution
   - Secure memory wiping after cryptographic operations
   - Protected LMK storage

3. **Access Control**
   - Command-level authorization
   - Secure logging of operations
   - Audit trail support

## Getting Started

### Prerequisites

- Go 1.24 or later
- TinyGo (for WASM compilation)
- GNU Make
- OpenSSL (for key generation)

### Initial Setup

1. Install TinyGo:
```bash
brew install tinygo
```

2. Install the plugin generator:
```bash
go install github.com/andrei-cloud/go_hsm/cmd/plugingen@latest
```

3. Generate an LMK (for development):
```bash
openssl rand -hex 24 > lmk.key
```

### Clone Repository

```bash
git clone https://github.com/andrei-cloud/go_hsm.git
cd go_hsm
```

### Build WASM Plugins

Compile all command plugins via Makefile:

```bash
make plugins
```

### Generate Plugin Wrappers

Run Go generate for all commands via Makefile (uses `plugingen`):

```bash
make gen
```

### Build the Server

Compile the server binary:

```bash
make build
```

### Build the CLI

Compile the CLI binary:

```bash
make cli
```

### Install the CLI

Install the CLI to your GOPATH/bin:

```bash
make install
```

### Run the Server

Start HSM server (JSON logs by default):

```bash
make run
```

For human-readable logs:

```bash
HUMAN=true DEBUG=true make run
```

### Testing

Run tests via Makefile:

```bash
make test
```

### Cleaning

Remove built binaries:

```bash
make clean
```

## CLI Usage

### HSM Server

Start the HSM server:

```bash
go_hsm serve
```

Options:
- `-p, --port`: Server port (default ":1500").
- `--lmk`: LMK hex value (default "0123456789ABCDEFFEDCBA9876543210").
- `--debug`: Enable debug logging.
- `--human`: Enable human-readable logs.
- `--plugin-dir`: Directory containing WASM plugins (default: `./plugins`).

### PIN Block Generation

Generate a PIN block:

```bash
go_hsm pinblock --pin 1234 --pan 4111111111111111 --format 01
```

List supported formats:

```bash
go_hsm pinblock --list-formats
```

## Writing a New Command

Follow the pattern of **A0** and **NC** commands.

### 1. Implement Business Logic

Create a new file in `internal/hsm/logic`, e.g. `FO.go`:

```go
// ExecuteFO handles the FO command payload.
func ExecuteFO(input []byte) ([]byte, error) {
    // parse input, call HSM, format response
    // use decryptUnderLMK(data) and encryptUnderLMK(data) functions and logDebug(msg) provided by the logic package.
}
```

The following host functions are exported to the WASM module and available in `internal/hsm/logic/host.go`:

```go
//go:wasm-module env
//export EncryptUnderLMK
func wasmEncryptUnderLMK(ptr, length uint32) uint64

//go:wasm-module env
//export DecryptUnderLMK
func wasmDecryptUnderLMK(ptr, length uint32) uint64

//go:wasm-module env
//export log_debug
func wasmLogToHost(s string)
```

Add unit tests in `internal/hsm/logic/FO_test.go`.

### 2. Add go:generate Stub

In `commands/FO/gen.go`:

```go
//go:generate plugingen \
//    -cmd=FO \
//    -logic=github.com/andrei-cloud/go_hsm/internal/hsm/logic \
//    -out=.
package main
```

### 3. Generate Wrapper

Run in the new command directory:

```bash
cd commands/FO
go generate
``` 

This creates `main.go` with the WASM exports.

### 4. Build the Plugin

Compile with TinyGo:

```bash
tinygo build -o ../FO.wasm -target=wasi -scheduler=none -opt=z -no-debug ./commands/FO/main.go
rm ./commands/FO/main.go
```

## Contributing

We welcome new commands and improvements!  
1. Fork the repository.  
2. Implement logic, wrapper stub, and tests.  
3. Submit a pull request describing your command and how it works.

## License

This project is licensed under the MIT License.