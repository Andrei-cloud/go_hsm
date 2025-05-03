# go_hsm

A Go-based, extendable implementation of HSM Module (Thales/Racal), featuring WASM plugin support and a clean command pattern for easy extension.

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
  - [Run the Server](#run-the-server)
  - [Testing](#testing)
  - [Cleaning](#cleaning)
- [Writing a New Command](#writing-a-new-command)
  - [1. Implement Business Logic](#1-implement-business-logic)
  - [2. Add go:generate Stub](#2-add-generate-stub)
  - [3. Generate Wrapper](#3-generate-wrapper)
  - [4. Build the Plugin](#4-build-the-plugin)
- [Contributing](#contributing)
- [License](#license)

## Introduction

go_hsm is a modular HSM server written in Go. It uses TinyGo to compile individual command handlers into WASM plugins, isolating business logic from WASM scaffolding. This design makes it easy to add new commands and maintain a clean codebase.

## Features

- Separate package for WASM memory and error helpers (`pkg/hsmplugin`).
- Business logic in `internal/hsm/logic`—one file per command.
- CLI tool (`cmd/plugingen`) to generate plugin wrappers.
- Hot-reload support via `SIGHUP`.
- Structured logging and error handling.

## Project Structure

```
├── cmd
│   ├── go_hsm         # Main HSM server
│   └── plugingen      # CLI to generate wrappers
├── commands          # Individual command plugins
│   ├── A0            # Command A0 source + go:generate
│   ├── NC            # Command NC source + go:generate
│   └── *.wasm        # Compiled WASM plugins
├── internal          # Server, plugins, logic, logging, errorcodes
│   ├── hsm
│   ├── logic
│   ├── plugins
│   └── server
├── pkg
│   ├── hsmplugin     # WASM helper utilities
│   └── cryptoutils
└── README.md
```

## Getting Started

### Prerequisites

- Go 1.24+
- TinyGo for WASM (`brew install tinygo`)
- GNU Make
- Makefile provides convenient targets (`make help`).
- Install the `plugingen` code generator:

```bash
go install github.com/andrei-cloud/go_hsm/cmd/plugingen@latest
```
Ensure `$GOPATH/bin` or `$HOME/go/bin` is in your `PATH`.

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

## Writing a New Command

Follow the pattern of **A0** and **NC** commands.

### 1. Implement Business Logic

Create a new file in `internal/hsm/logic`, e.g. `FO.go`:

```go
// ExecuteFO handles the FO command payload.
func ExecuteFO(
  input []byte,
  decryptUnderLMK func([]byte) ([]byte, error),
  encryptUnderLMK func([]byte) ([]byte, error),
  logFn func(string),
) ([]byte, error) {
  // parse input, call HSM, format response
}
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