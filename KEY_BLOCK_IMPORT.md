# Key Block Import Implementation

This document describes the implementation of key block import functionality in the HSM keys import command.

## Overview

The `keys import` command now supports importing clear keys under both Variant LMK and Key Block LMK formats, determined by the `--lmk-id` flag:

- `--lmk-id 00`: Uses Variant LMK (existing functionality)
- `--lmk-id 01`: Uses Key Block LMK with interactive header configuration (new functionality)

## Key Block Import Flow

When using `--lmk-id 01`, the import process follows these steps:

1. **Clear Key Input**: User provides clear key in hex format via `--key` flag
2. **Interactive Header Configuration**: TUI launches for configuring all key block header parameters (including key usage)
3. **Key Block Creation**: Clear key is wrapped using configured header
4. **Output**: Display key type, key block (ASCII format), and KCV

**Note**: The `--type` flag is not required for key block imports as the key usage is configured interactively in the TUI.

## Interactive TUI Features

The Terminal User Interface (TUI) provides:

### Radio Button Fields
- **Version**: "0" (3-DES protected) or "1" (AES protected)
- **Key Usage**: 50+ predefined TR-31 compliant options (B0-B2, C0, D0-D2, E0-E6, G0, I0, K0-K3, M0-M8, P0-P1, S0-S2, T0-T1, V0-V5, X0-X1, Y0)
- **Algorithm**: AES, DES, Elliptic Curve, RSA, DSA, Triple DES
- **Mode of Use**: Encrypt/Decrypt, Generate/Verify, etc.
- **Exportability**: Exportable, Non-exportable, Sensitive

### Numeric Input Field
- **Key Version Number**: 00-99 with direct numeric input, increment/decrement, and validation
  - "00" means key versioning is not used (TR-31 default)
  - "01"-"99" represent actual key versions
  - Note: TR-31 also supports key components ("c1"-"c9") and custom versions, but the TUI currently supports numeric versions only

### Navigation
- **↑/↓ or j/k**: Select options or increment/decrement values
- **Tab/Shift+Tab**: Navigate between fields
- **Enter**: Confirm and proceed to next field
- **0-9**: Direct numeric input for version number
- **Backspace**: Delete digits in numeric fields
- **q or Ctrl+C**: Quit

## Usage Examples

### Variant LMK Import (Existing)
```bash
./go_hsm keys import --key 0123456789ABCDEF --type 000 --lmk-id 00
```

Output:
```
Auto-detected scheme: X (8 bytes)
Key Type: Name: ZMK, Code: 000, LMKPairIndex: 2, VariantID: 0
Key Scheme: X
Parity Check: true
Encrypted Key: X42BBE7D9A0A55D0E
KCV: D5D44F
```

### Key Block LMK Import (New)
```bash
./go_hsm keys import --key 0123456789ABCDEF --lmk-id 01
```

This launches the interactive TUI where users can configure:
- Version: "1" (AES protected)
- Key Usage: Any of the 50+ available TR-31 compliant options (B0-B2, C0, D0-D2, E0-E6, G0, I0, K0-K3, M0-M8, P0-P1, S0-S2, T0-T1, V0-V5, X0-X1, Y0)
- Algorithm: "A" (AES)
- Mode of Use: "N" (No special restrictions)
- Key Version Number: "00" (user configurable 00-99)
- Exportability: "S" (Sensitive)

Output:
```
Importing key under Key Block LMK...
[Interactive TUI here]
Key Type: G0
Key Block: S10000G0TN00S00007CFCA2423747C444722B9289BC1D462CBD50CBDC40126F40
KCV: D5D44F
```

## Technical Implementation

### Files Modified
- `internal/commands/cli/keys/import.go`: Main import logic with LMK type detection
- `internal/commands/cli/keys/keyblock_tui.go`: Interactive TUI implementation
- `internal/hsm/logic/lmk_provider.go`: Added WrapWithHeader method

### Key Components
1. **Field Types**: Radio button and numeric input field types
2. **Model State**: Tracks current field, selections, and header configuration
3. **Input Handling**: Keyboard navigation and data entry
4. **Header Mapping**: Maps TUI selections to key block header structure
5. **Validation**: Numeric range checking and bounds enforcement

### Dependencies Added
- `github.com/charmbracelet/bubbletea`: For interactive TUI framework

## Testing

Comprehensive tests cover:
- TUI model initialization and state management
- Numeric field operations (increment, decrement, input, validation)
- Header update logic and field mapping
- Integration test for complete key block wrap/unwrap cycle

All tests pass and verify correct functionality.
