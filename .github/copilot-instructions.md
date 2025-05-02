###Coding Rules:
* All coments must end in a period.
* ```return``` and ```continue``` should have an empty line before.
* follow declaration order as: ```const```, ```var```, ```type``` and only after their methods.
* type must not be placed after func (desired order: const,var,type,func)
* error-strings: error strings should not be capitalized or end with punctuation or a newline.
* empty-lines: shoud not be an extra empty line at the start of a block
* use-any: since Go 1.18 'interface{}' can be replaced by 'any' (revive)

# copilot_instructions.md

## Overview  
These instructions guide a GitHub Copilot–style agent to refactor the **go_hsm** repo for reusable WASM-plugin scaffolding. You will:

1. Extract common memory-management and helper routines into a shared package.  
2. Pull business-logic out into `internal/hsm/logic`.  
3. Create a `plugingen` CLI to emit boilerplate wrappers.  
4. Wire up `//go:generate` in each plugin directory.  
5. Update build scripts and tests.  

---

## Coding Standards  
- **Formatting**: Run `go fmt` on every file.  
- **Linting**: Ensure `go vet` and `golangci-lint run` pass zero errors.  
- **Error Handling**: Return `error` values; never log or panic inside library code.  
- **Naming**:  
  - Shared helpers package: `pkg/hsmplugin`  
  - Business logic: `internal/hsm/logic/Execute<Cmd>`  
  - Generator CLI: `cmd/plugingen`  
- **Documentation**: Every public function must have a GoDoc comment.  
- **Testing**:  
  - Unit tests for `pkg/hsmplugin`  
  - Validate generated wrapper compiles  

---

## Implementation Steps

### 1. Extract shared WASM-helper package  
- **Create** directory `pkg/hsmplugin`.  
- **Implement** in `allocator.go`:  
  ```go
  var nextPtr uint32
  func ResetAllocator() { nextPtr = 8 }
  func Alloc(n uint32) uint32 { /* bump-allocate with 8-byte alignment */ }
  func Free(ptr uint32) { /* no-op or future reclaim logic */ }
  ```
- **Implement** in `memory.go`:
```go
func ReadBytes(ptr, len uint32) []byte { /* unsafe slice */ }
func WriteBytes(ptr uint32, data []byte) { /* copy into linear memory */ }
```
- **Implement** in `result.go`:
```go
func PackResult(ptr, len uint32) uint64 { /* high<<32 | low */ }
func WriteError(cmd string) uint64 { /* alloc + write “<cmd>86” */ }
```
	Write unit tests covering allocator, Read/Write, PackResult, WriteError.

### 2. Isolate business logic
	•	Create internal/hsm/logic directory.
	•	For each command (e.g. NC):
	•	File NC.go with:
    ```go
    // ExecuteNC processes the NC payload and returns response bytes.
        func ExecuteNC(input []byte) ([]byte, error) {
        // parse, compute KCV, append firmware
        }
    ```
    •	Doc the function with a GoDoc comment.
	•	Test each logic function in _test.go files.

### 3. Build the plugingen tool
	•	Create cmd/plugingen with its own go.mod.
	•	Write main.go that:
	•	Parses flags: -cmd, -logic, -out.
	•	Uses text/template to render a main.go wrapper from this template:

    ```gotemplate
    package main

import (
  "github.com/andrei-cloud/go_hsm/pkg/hsmplugin"
  "{{.LogicImport}}"
)

//export Alloc
func Alloc(size uint32) uint32 { return hsmplugin.Alloc(size) }
//export Free
func Free(ptr uint32) { hsmplugin.Free(ptr) }
//export Execute
func Execute(ptr, length uint32) uint64 {
  hsmplugin.ResetAllocator()
  in := hsmplugin.ReadBytes(ptr, length)
  out, err := logic.Execute{{.Cmd}}(in)
  if err != nil {
    return hsmplugin.WriteError("{{.Cmd}}")
  }
  p := hsmplugin.Alloc(uint32(len(out)))
  hsmplugin.WriteBytes(p, out)
  return hsmplugin.PackResult(p, uint32(len(out)))
}
func main() {}
    ```

Install it via go install.

### 4. Wire up go:generate in each plugin
	•	In commands/<Cmd>/gen.go, add:
    ```go
    //go:generate plugingen \
    //    -cmd=<Cmd> \
    //    -logic=github.com/andrei-cloud/go_hsm/internal/hsm/logic/<Cmd> \
    //    -out=.
    package main
    ```
	Remove any existing boilerplate main.go in that directory.
	•	Run go generate ./commands/<Cmd> to produce a fresh main.go.

### 5. Documentation
	•	Add a “Plugin Authoring” section to the root README.md:
	•	Describe pkg/hsmplugin API.
	•	Show sample gen.go and usage.
	•	Explain internal/hsm/logic convention.
	•	Ensure all code samples and import paths are correct.