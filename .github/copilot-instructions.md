# Copilot Instructions

## Coding Rules:
* All comments must end in a period.  
* `return` and `continue` should have an empty line before.  
* Declaration order: `const`, `var`, `type`, then `func`.  
* `type` declarations must not come after functions.  
* error strings should not be capitalized or end with punctuation or a newline.  
* No extra empty line at the start of a block.  
* Replace `interface{}` with `any` when possible (Go 1.18+).

# Development Plan for CLI Implementation

## Project Structure

```
go_hsm/
├── cmd/
│   └── go_hsm/
│       ├── main.go                  # CLI entry point
│       └── cmd/                     # CLI commands package
│           ├── root.go              # Root command definition
│           ├── serve.go             # Server command (existing functionality)  
│           └── pinblock.go          # PIN block generation command
├── internal/
│   ├── cli/                         # CLI-specific utilities
│   │   ├── format.go                # Output formatting helpers
│   │   └── pinblock.go              # PIN block CLI operations
│   ├── hsm/                         # Existing HSM implementation
│   ├── logging/                     # Existing logging functionality
│   ├── plugins/                     # Plugin system
│   └── server/                      # Server implementation
└── pkg/
    └── pinblock/                    # Existing PIN block implementation
```

## Implementation Steps

### 1. Set Up Project Structure and Dependencies

1. Add Cobra dependency:
   ```bash
   go get -u github.com/spf13/cobra@latest
   ```

2. Create directory structure:
   ```bash
   mkdir -p cmd/go_hsm/cmd internal/cli
   ```

### 2. Implement Root Command

Create `cmd/go_hsm/cmd/root.go`:
```go
// Package cmd provides the CLI commands for the go_hsm application.
package cmd

import (
    "github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
    Use:   "go_hsm",
    Short: "Hardware Security Module server and utilities",
    Long:  `A flexible HSM server and utility tool for PIN block operations and other cryptographic functions for payment card processing.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
    return rootCmd.Execute()
}
```

### 3. Implement Serve Command (Existing Functionality)

Move existing functionality from `cmd/go_hsm/main.go` to `serve.go`.

### 4. Implement CLI Helper Functions

Create `internal/cli/format.go`:
```go
// Package cli contains utilities for CLI operations.
package cli

import (
    "fmt"
    "github.com/andrei-cloud/go_hsm/internal/hsm"
)

// GetSupportedPinBlockFormats returns a map of Thales format codes to readable format descriptions.
func GetSupportedPinBlockFormats() map[string]string {
    return map[string]string{
        "01": "ISO 9564-1 Format 0 (ANSI X9.8)",
        "02": "Docutel Format",
        "03": "Diebold/IBM 3624 Format",
        "04": "PLUS Network Format",
        "05": "ISO 9564-1 Format 1",
        "34": "ISO 9564-1 Format 2",
        "35": "Mastercard Pay Now & Pay Later Format",
        "41": "Visa PIN-only Change Format",
        "42": "Visa Old+New PIN Change Format",
        "47": "ISO 9564-1 Format 3",
        "48": "ISO 9564-1 Format 4",
    }
}

// PrintSupportedFormats prints the supported PIN block formats in a readable format.
func PrintSupportedFormats() {
    formats := GetSupportedPinBlockFormats()
    fmt.Println("Supported PIN block formats:")
    fmt.Println("----------------------------")
    for code, desc := range formats {
        fmt.Printf("%s: %s\n", code, desc)
    }
}
```

### 5. Implement PinBlock Command

Create `cmd/go_hsm/cmd/pinblock.go`:
```go
package cmd

import (
    "fmt"
    "github.com/andrei-cloud/go_hsm/internal/cli"
    "github.com/spf13/cobra"
)

var (
    pin         string
    pan         string
    formatCode  string
    listFormats bool
)

// pinblockCmd represents the pinblock command.
var pinblockCmd = &cobra.Command{
    Use:   "pinblock",
    Short: "Generate PIN block in specified format",
    Long: `Generate PIN block using specified PIN, PAN, and Thales format code.
Supported formats can be listed using the --list-formats flag.`,
    Example: `  # Generate ISO Format 0 PIN block
  go_hsm pinblock --pin 1234 --pan 4111111111111111 --format 01

  # List supported formats
  go_hsm pinblock --list-formats`,
    RunE: func(cmd *cobra.Command, args []string) error {
        if listFormats {
            cli.PrintSupportedFormats()
            return nil
        }

        if pin == "" || pan == "" || formatCode == "" {
            return fmt.Errorf("pin, pan, and format are required")
        }

        result, err := cli.GeneratePinBlock(pin, pan, formatCode)
        if err != nil {
            return err
        }

        fmt.Printf("PIN Block (%s): %s\n", formatCode, result)
        return nil
    },
}

func init() {
    rootCmd.AddCommand(pinblockCmd)

    pinblockCmd.Flags().StringVar(&pin, "pin", "", "PIN number (4-12 digits)")
    pinblockCmd.Flags().StringVar(&pan, "pan", "", "Primary Account Number (card number)")
    pinblockCmd.Flags().StringVar(&formatCode, "format", "", "Thales format code (e.g., 01 for ISO 0)")
    pinblockCmd.Flags().BoolVar(&listFormats, "list-formats", false, "List supported PIN block formats")
}
```

### 6. Update Main Entry Point

Update `cmd/go_hsm/main.go`:
```go
package main

import (
    "os"
    "github.com/andrei-cloud/go_hsm/cmd/go_hsm/cmd"
)

func main() {
    if err := cmd.Execute(); err != nil {
        os.Exit(1)
    }
}
```

### 7. Add Makefile Targets

Update the Makefile with CLI-specific targets:
```makefile
.PHONY: cli install

cli: ## Build CLI binary.
	go build -o bin/go_hsm ./cmd/go_hsm

install: cli ## Install CLI to GOPATH/bin.
	cp bin/go_hsm $(GOPATH)/bin/
```

### 8. Testing Plan

1. Create unit tests for CLI functionality:
   - PIN block generation.
   - Format listing.
   - Flag validation.

2. Create integration tests for CLI commands:
   - Test `serve` command startup.
   - Test `pinblock` command with various formats.
   - Test error handling.

### 9. Documentation Updates

Update `README.md` with CLI usage examples:
```markdown
## CLI Usage

### HSM Server

Start the HSM server:

```bash
go_hsm serve
```

Options:
- `--port, -p`: Server port (default: 1500).
- `--lmk`: LMK hex value (default: from HSM_LMK environment variable).
- `--debug`: Enable debug logging.
- `--human`: Enable human-readable logs.

### PIN Block Generation

Generate a PIN block:

```bash
go_hsm pinblock --pin 1234 --pan 4111111111111111 --format 01
```

List supported PIN block formats:

```bash
go_hsm pinblock --list-formats
```

### 10. Implementation Schedule

1. **Day 1**: Set up project structure and dependencies.
   - Add Cobra dependency.
   - Create directory structure.
   - Implement root command structure.

2. **Day 2**: Implement serve command.
   - Move server code from `main.go` to `serve.go`.
   - Add command-specific flags.
   - Test server startup and operation.

3. **Day 3**: Implement pinblock command.
   - Create CLI helper utilities.
   - Implement PIN block generation logic.
   - Implement format listing.

4. **Day 4**: Testing and refinement.
   - Write unit tests for CLI functionality.
   - Write integration tests for CLI commands.
   - Debug and fix issues.

5. **Day 5**: Documentation and finalization.
   - Update `README.md` with CLI usage examples.
   - Add examples for `serve` and `pinblock` commands.
   - Perform final testing and validation.

