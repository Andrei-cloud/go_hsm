# go_hsm

go_hsm is a Go-based HSM server framework with support for WASM plugins.

## Plugin Authoring

### Shared Helpers (`pkg/hsmplugin`)

The `pkg/hsmplugin` package provides common functions for memory management and result packing in WASM plugins:

- `ResetAllocator()` resets the linear allocator to the initial offset.
- `Alloc(n uint32) uint32` allocates `n` bytes aligned to 8-byte boundaries.
- `Free(ptr uint32)` releases memory (no-op currently).
- `ReadBytes(ptr, length uint32) []byte` reads a slice from WASM linear memory.
- `WriteBytes(ptr uint32, data []byte)` writes data into WASM linear memory.
- `PackResult(ptr, length uint32) uint64` combines a pointer and length into a 64-bit result.
- `WriteError(cmd string) uint64` allocates and writes an error code for a given command.

### Business Logic (`internal/hsm/logic`)

Each HSM command should implement its core logic in `internal/hsm/logic`:

```go
// ExecuteNC processes the NC payload and returns response bytes.
func ExecuteNC(input []byte) ([]byte, error) { /* ... */ }
```

This keeps business rules separate from WASM scaffolding. Unit tests should accompany each logic file.

### Wrapper Generation (`cmd/plugingen`)

The `plugingen` CLI emits boilerplate wrappers for a given command and logic path. Its flags:

- `-cmd` : Command name (e.g. `NC`).
- `-logic` : Import path to the logic package (e.g. `github.com/andrei-cloud/go_hsm/internal/hsm/logic/NC`).
- `-out` : Output directory for the generated `main.go`.

Example:

```shell
plugingen -cmd=NC \
    -logic=github.com/andrei-cloud/go_hsm/internal/hsm/logic \
    -out=commands/NC
```

### go:generate Stub

In each `commands/<Cmd>/gen.go`, add:

```go
//go:generate plugingen \
//    -cmd=<Cmd> \
//    -logic=github.com/andrei-cloud/go_hsm/internal/hsm/logic \
//    -out=.
package main
```

Run:

```shell
go generate ./commands/NC
``` 
or
```shell
go generate ./...
``` 

to produce the plugin wrapper.

### Building and Testing

- Generate all plugins:
  ```shell
  make plugins
  ```
- Run the HSM server:
  ```shell
  make run
  ```
- Execute tests:
  ```shell
  go test ./...
  ```

This guide ensures consistent plugin authoring and safe WASM integration.