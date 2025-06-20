# go_hsm

A Go-based Hardware Security Module (HSM) implementation compatible with Thales/Racal protocols, featuring a WASM-based plugin architecture for command extensibility and hot-reload.

> **Unleash your creativity: Easily add new HSM commands as plugins—contribute your own or extend the system for your needs!**

---

## Table of Contents

- [Features](#features)
- [Implemented HSM Commands](#implemented-hsm-commands)
- [Quick Start](#quick-start)
- [Testing the HSM Server](#testing-the-hsm-server)
- [CLI Commands](#cli-commands)
- [Project Structure](#project-structure)
- [Plugin System Overview](#plugin-system-overview)
- [Server Operation](#server-operation)
- [Development Workflow](#development-workflow)
- [Makefile Targets](#makefile-targets)
- [Security Features](#security-features)
- [Contributing](#contributing)
- [License](#license)
- [Author & Attribution](#author--attribution)

---

## Features

- ☑️ Memory-efficient buffer pooling for high-throughput environments.
- ☑️ WASM-based plugin system for secure, isolated, and extensible command implementation.
- ☑️ Hot-reload support: reload plugins at runtime with SIGHUP, no server restart required.
- ☑️ CLI for server management, plugin management, and cryptographic utilities.
- ☑️ Compatible with Thales/Racal HSM protocols and standard PIN block formats.
- ☑️ Table-driven tests and example-driven documentation for all exported APIs.
- ☑️ Structured logging and error handling for robust production and development use.
- ☑️ **Complete support for standard Thales test Variant LMK**.
- ☑️ **Key block (TR-31 and Thales) support with parsing and validation**.
- ⏳ Additional HSM commands (pending).

---

## Implemented HSM Commands

The following HSM commands are currently implemented as WASM plugins:

| Command | Description |
|---------|-------------|
| **A0** | Generate a random key |
| **B2** | Echo test command | 
| **BU** | Generate Key Check Value |
| **CA** | Translate PIN block |
| **CW** | Generate CVV |
| **CY** | Verify CVV |
| **DC** | Translate and verify PIN |
| **EC** | Verify Terminal PIN with offset |
| **FA** | Translate ZMK to ZPK |
| **HC** | Generate TMK/TPK/PVK |
| **NC** | Network diagnostics |
| **KQ** | ARQC verification and/or ARPC generation |

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
5. Generate cryptographic keys:
   ```bash
   ./bin/go_hsm keys generate --type 000 --scheme X
   ```

## Testing the HSM Server

Once the server is running, you can test HSM commands using the provided scripts. Here are some examples:

### Example 1: Generate Key (A0 Command)
```bash
echo -ne 'A00001U' | ./script/send_with_length.sh 127.0.0.1 1500
```

**Output:**
```
sending message from stdin (1 times)
request 1/1:
00000000  00 0b 00 00 03 7f 41 30  30 30 30 31 55           |......A00001U|
0000000d
00000000  00 2f 00 00 03 7f 41 31  30 30 55 33 35 42 36 45  |./....A100U35B6E|
00000010  44 35 34 43 41 30 42 38  39 36 39 38 30 43 31 32  |D54CA0B896980C12|
00000020  44 46 44 34 36 45 42 30  42 39 35 46 37 42 38 35  |DFD46EB0B95F7B85|
00000030  38                                                |8|
00000031
```

This shows:
- **Request**: `A00001U` (Generate key with key type `000` mode `1` and modifier `U`)
- **Response**: `A100U35B6ED54CA0B896980C12DFD46EB0B95F7B858` (Success with generated key)

### Example 2: Network Connect (NC Command)
```bash
echo -ne 'NC' | ./script/send_with_length.sh 127.0.0.1 1500
```

**Output:**
```
sending message from stdin (1 times)
request 1/1:
00000000  00 06 00 00 03 80 4e 43                           |......NC|
00000008
00000000  00 21 00 00 03 80 4e 44  30 30 30 30 30 30 30 30  |.!....ND00000000|
00000010  30 30 30 30 30 30 30 30  30 30 37 30 30 30 2d 45  |00000000007000-E|
00000020  30 30 30                                          |000|
00000023
```

This shows:
- **Request**: `NC` (Diagnostics)
- **Response**: `ND00000000000000007000-E000` (Network status with firmware version information)

### Understanding the Message Format

The scripts automatically handle the Thales/Racal message format:
- **2-byte length prefix**: Total message length (header + payload)
- **4-byte header**: Incremental counter for message tracking
- **Payload**: The actual HSM command and response

The hexdump output shows both the raw binary data and ASCII representation, making it easy to verify message structure and content.

### Advanced Testing with Binary Field Formatting

For more complex HSM commands that require binary data fields, use the `parse_command.sh` script. This script supports various field formats and automatically handles binary data conversion.

#### Script: `parse_command.sh`

The `parse_command.sh` script parses commands with specialized field formatting and sends them to the HSM server.

**Usage:**
```bash
./script/parse_command.sh <command_string> <host> <port>
```

**Field Format Support:**
- `8B:1111111111111100` - 8 bytes binary (hex value converted to binary)
- `2H:74` - 2 hex characters representing decimal value 74 as hex "4A"
- `4B:52BF4585` - 4 bytes binary (hex value converted to binary)
- `B:0000000123...;` - variable length binary (until ';', delimiter included in output)
- `|` - field delimiter
- No prefix - value passed as-is

#### Example 3: Complex Command with Binary Fields
```bash
./script/parse_command.sh "KQ00U7475636CC30B93B493CF5EA53799EBCC|8B:1111111111111100|2B:005E|4B:52BF4585|2H:37|B:0000000123000000000000000784800004800008402505220052BF45851800005E06011203;|8B:076C5766F738E9A6" 127.0.0.1 1500
```

Output:
```
parsed message hex: 4b5130305537343735363336434333304239334234393343463545413533373939454243431111111111111100005e52bf458532350000000123000000000000000784800004800008402505220052bf45851800005e060112033b076c5766f738e9a6
sending message from stdin (1 times)
request 1/1:
00000000  00 67 00 00 03 b7 4b 51  30 30 55 37 34 37 35 36  |.g....KQ00U74756|
00000010  33 36 43 43 33 30 42 39  33 42 34 39 33 43 46 35  |36CC30B93B493CF5|
00000020  45 41 35 33 37 39 39 45  42 43 43 11 11 11 11 11  |EA53799EBCC.....|
00000030  11 11 00 00 5e 52 bf 45  85 32 35 00 00 00 01 23  |....^R.E.25....#|
00000040  00 00 00 00 00 00 00 07  84 80 00 04 80 00 08 40  |...............@|
00000050  25 05 22 00 52 bf 45 85  18 00 00 5e 06 01 12 03  |%.".R.E....^....|
00000060  3b 07 6c 57 66 f7 38 e9  a6                       |;.lWf.8..|
00000069
00000000  00 08 00 00 03 b7 4b 52  30 30                    |......KR00|
0000000a
```

#### Example 4: ARQC Verification / ARPC Generation (KQ Command)

```bash
./bin/go_hsm keys generate --type 000 --scheme U
```

**Options:**
- `--type`: Key type code (000, 001, 002, etc.)
- `--scheme`: LMK encryption scheme (X=single, U=double, T=triple length) - defaults to U
- `--clear`: Display the clear key value (for testing/development only)
- `--pci`: Enable PCI compliance mode

**Examples:**

Generate a ZMK (Zone Master Key) with double-length scheme:
```bash
./bin/go_hsm keys generate --type 000 --scheme U
```
Output:
```
Key Type: Name: ZMK, Code: 000, LMKPairIndex: 2, VariantID: 0
Key Scheme: U
Encrypted Key: UC734ACEC91D7DBBBB2EA63EAF3F6E4DA
KCV: E5EEC3
```

Generate a ZPK (Zone PIN Key) with single-length scheme and show clear key:
```bash
./bin/go_hsm keys generate --type 001 --scheme X --clear
```
Output:
```
Key Type: Name: ZPK, Code: 001, LMKPairIndex: 3, VariantID: 0
Key Scheme: X
Encrypted Key: X05419331EC21E4B2
KCV: 78A6D9
Clear Key: DF40519B0775B3B9
```

Generate a PVK (PIN Verification Key) with triple-length scheme:
```bash
./bin/go_hsm keys generate --type 002 --scheme T
```
Output:
```
Key Type: Name: PVK/Generic, Code: 002, LMKPairIndex: 7, VariantID: 0
Key Scheme: T
Encrypted Key: T7A4F2E108196A74279084233FC75A4E05FFCFE594A2E3DF0
KCV: 2D6D77
```

Generate a key in PCI compliance mode:
```bash
./bin/go_hsm keys generate --type 001 --scheme X --pci
```
Output:
```
Key Type: Name: ZPK, Code: 001, LMKPairIndex: 3, VariantID: 0
Key Scheme: X
Encrypted Key: XA6968DC16A7B66B3
KCV: A37A9C
```

#### Import Keys

Import clear keys with automatic validation and LMK encryption:

```bash
./bin/go_hsm keys import --key DF40519B0775B3B9 --type 001 --scheme X
```

**Options:**
- `--key`: Clear key in hexadecimal format (16, 32, or 48 hex characters)
- `--type`: Key type code (000, 001, 002, etc.)
- `--scheme`: LMK encryption scheme (optional, auto-detected based on key length if not specified)
- `--force-parity`: Fix key parity if invalid (DES keys only)
- `--pci`: Enable PCI compliance mode

**Examples:**

Import a single-length key with explicit scheme:
```bash
./bin/go_hsm keys import --key DF40519B0775B3B9 --type 001 --scheme X
```
Output:
```
Key Type: Name: ZPK, Code: 001, LMKPairIndex: 3, VariantID: 0
Key Scheme: X
Encrypted Key: X05419331EC21E4B2
KCV: 78A6D9
```

Import a double-length key with automatic scheme detection:
```bash
./bin/go_hsm keys import --key 1234567890ABCDEF1234567890ABCDEF --type 000 --force-parity
```
Output:
```
Warning: Key parity was invalid and has been fixed
Key Type: Name: ZMK, Code: 000, LMKPairIndex: 2, VariantID: 0
Key Scheme: U
Encrypted Key: U04A3A0285B653284CB52D0F5C1E3E835
KCV: A50201
```

Import a triple-length key with automatic scheme detection:
```bash
./bin/go_hsm keys import --key 1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF --type 002 --force-parity
```
Output:
```
Warning: Key parity was invalid and has been fixed
Key Type: Name: PVK/Generic, Code: 002, LMKPairIndex: 7, VariantID: 0
Key Scheme: T
Encrypted Key: TE0D7478DC363B5E2BE08F7253E80A37DDB4817AD5700B96B
KCV: A50201
```

Import with force parity correction:
```bash
./bin/go_hsm keys import --key DF40519B0775B3B8 --type 001 --scheme X --force-parity
```
Output:
```
Warning: Key parity was invalid and has been fixed
Key Type: Name: ZPK, Code: 001, LMKPairIndex: 3, VariantID: 0
Key Scheme: X
Encrypted Key: X05419331EC21E4B2
KCV: 78A6D9
```

#### Key Types Reference

| Type | Name | Description |
|------|------|-------------|
| 000 | ZMK | Zone Master Key |
| 001 | ZPK | Zone PIN Key |
| 002 | PVK/Generic | PIN Verification Key |
| 003 | TMK | Terminal Master Key |
| 004 | TPK | Terminal PIN Key |
| 009 | ZMAC | Zone MAC Key |

#### LMK Schemes Reference

| Scheme | Description | Key Length |
|--------|-------------|------------|
| X | Single-length DES | 8 bytes (16 hex chars) |
| U | Double-length 3DES | 16 bytes (32 hex chars) |
| T | Triple-length 3DES | 24 bytes (48 hex chars) |

#### Error Handling

The CLI provides comprehensive error checking and validation:

- **Key parity validation**: DES keys are automatically checked for odd parity
- **Automatic scheme detection**: Key length determines scheme if not specified
- **Invalid hex format**: Clear error messages for non-hexadecimal input
- **Invalid key lengths**: Must be 16, 32, or 48 hexadecimal characters
- **PCI compliance**: Secure handling in production environments

If a key fails parity validation without `--force-parity`, the command will exit with an error. Use `--force-parity` to automatically correct parity bits before importing.

**Key Block Parsing Options:**
- `--keyblock`: Key block string to parse (Thales 'S', 'K', or TR-31 'R' format)
- `--lmk-index`: LMK index for key block validation (optional)

**Example: Parse Thales Key Block**
```bash
./bin/go_hsm keys check --keyblock S1009651TB00S00003F7FA0520BABA0C6A99E88E82D48040FA4826CA256996A532A1E0059A90B472E477C5926420CA4C7
```
Output:
```
Header (16 bytes)
Offset   Field                       Value   Meaning
0        Version ID                  1       Thales Key Block protected by an AES key
1-4      Key Block length            0096    Total length of key block: 96 bytes
5-6      Key usage                   51      3DES Terminal Key Encryption (TMK)
7        Algorithm                   T       3-DES
8        Mode of use                 B       Both encrypt and decrypt
9-10     Key Version Number          00      Key versioning not used
11       Exportability               S       Sensitive; all other export possibilities permitted
12-13    Number of optional blocks   00      0 optional blocks
14-15    LMK ID                      00      LMK ID 00 (default LMK)

Encrypted Key Data (72 bytes)
3F7FA0520BABA0C6A99E88E82D48040F
A4826CA256996A532A1E0059A90B472E
477C5926

Key Block Authenticator (MAC)
420CA4C7

Key Block Summary:
- Format: S (Thales Secure Key Block)
- Total Length: 96 bytes
- Header: 16 bytes
- Optional Headers: 0 bytes (0 blocks)
- Encrypted Key Data: 72 bytes
- MAC: 8 bytes

Key block parsed successfully. Provide --lmk-index to validate.
```

#### Key Block Format Support

The go_hsm system now includes comprehensive support for industry-standard key blocks:

**Supported Formats:**
- **Thales 'S' Format**: Proprietary Thales key block format with 8-byte MAC
- **TR-31 'R' Format**: Standard ANSI X9 TR-31 key blocks with 16-byte MAC
- **Mixed Encoding**: Thales format with ASCII headers and hex-encoded data

**Key Block Features:**
- **Header Parsing**: Complete analysis of 16-byte headers with field-by-field breakdown
- **Optional Blocks**: Support for optional header blocks with TLV structure parsing
- **MAC Verification**: Integrity checking using AES-CMAC authentication
- **Multiple Algorithms**: Support for AES and 3DES key protection
- **Format Detection**: Automatic detection of key block format and structure

**Key Block Structure Analysis:**
The check command provides detailed analysis including:
- Version identification (AES vs 3DES protection)
- Key usage codes and meanings
- Algorithm and mode of use
- Exportability restrictions  
- Optional header block parsing
- Encrypted key data visualization
- MAC/authenticator verification
- Summary statistics

### Other CLI Commands

#### Server Management
```bash
# Start HSM server
./bin/go_hsm serve --port 1500 --plugin-dir=./plugins

# Generate PIN blocks
./bin/go_hsm pinblock --pin 1234 --pan 4111111111111111 --format 01
```

#### Plugin Management
```bash
# Create new plugin
./bin/go_hsm plugin create FO --desc "Format Output" --version 1.0.0 --author "Alice"
```

---

## Key Block Implementation (keyblocklmk Package)

The `keyblocklmk` package provides comprehensive implementation of Thales and TR-31 key block standards, representing a significant enhancement over the main branch's basic variant LMK support.

### Key Differences from Main Branch

#### Main Branch Capabilities
- **Variant LMK System**: Traditional Thales Variant LMK encryption using static variant bytes
- **DES-based Protection**: 3DES encryption with variant-modified LMK pairs
- **Basic Key Management**: Generate, import, and check keys with simple schemes (X, U, T)
- **Limited Standards Support**: Proprietary Thales variant scheme only

#### New Key Block Branch Features

**Enhanced Cryptographic Foundation:**
- **AES-256 LMK**: Modern AES-256 base Local Master Key instead of DES-based variants
- **CMAC-based Key Derivation**: Cryptographically secure key derivation using AES-CMAC per ISO 20038
- **Strong MAC Authentication**: AES-CMAC for integrity protection instead of basic checksums

**Industry Standard Compliance:**
- **TR-31 Support**: Full ANSI X9 TR-31 key block standard implementation
- **Thales Format 'S'**: Native support for Thales proprietary key block format  
- **Mixed Format Handling**: Automatic detection and parsing of different key block types
- **Header Field Parsing**: Complete analysis of 16-byte headers with semantic interpretation

**Advanced Key Protection:**
- **Key Block Encryption**: Secure key wrapping using derived KBEK (Key Block Encryption Key)
- **Integrity Binding**: MAC covers both key data and metadata for tamper detection
- **Optional Header Blocks**: Support for extensible metadata in TLV format
- **Format-Specific MAC**: 8-byte MAC for Thales 'S', 16-byte MAC for TR-31 'R'

#### Key Block Structure
```
┌─────────────────┬─────────────────┬─────────────────┬─────────────────┐
│ Header (16B)    │ Optional Blocks │ Encrypted Key   │ MAC (8B/16B)    │
│ - Version       │ - TLV Structure │ - AES-CBC       │ - AES-CMAC      │
│ - Usage/Algorithm│ - Metadata     │ - Length prefix │ - Truncated (S) │
│ - Exportability │ - Extensions    │ - Random padding│ - Full MAC (R)  │
└─────────────────┴─────────────────┴─────────────────┴─────────────────┘
```

#### Security Enhancements
- **IV Binding**: CBC IV derived from header ensures header integrity
- **Authenticated Encryption**: MAC covers header + optional blocks + ciphertext  
- **Length Protection**: Key bit length embedded in plaintext prevents substitution
- **Format Validation**: Comprehensive parsing with error detection

### Use Cases and Benefits

**Enterprise Integration:**
- **HSM Interoperability**: Compatible with Thales payShield, SafeNet, and other HSMs
- **Standard Compliance**: Meets PCI DSS requirements for key protection
- **Audit Trail**: Detailed parsing for compliance reporting
- **Migration Support**: Bridge between proprietary and standard formats

**Development and Testing:**
- **Format Validation**: Verify key block structure and integrity
- **Debugging Tools**: Field-by-field analysis for troubleshooting
- **Test Vector Support**: Compatible with industry test vectors
- **Cross-Platform**: Pure Go implementation for portability

**Security Advantages:**
- **Cryptographic Agility**: Modern AES-256 foundation
- **Tamper Detection**: Strong MAC authentication  
- **Forward Compatibility**: Extensible header format
- **Standards Alignment**: Industry-proven key protection methods

The key block implementation represents a significant advancement in cryptographic key management, moving from proprietary variant schemes to industry-standard key protection mechanisms while maintaining backward compatibility and ease of use.

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

- `make help`       - Display help screen with available targets.
- `make gen`        - Generate new plugin code and WASM wrappers.
- `make plugins`    - Build all WASM plugins (or a single one with `CMD=NAME`).
- `make run`        - Start HSM server with debug logging on port 1500.
- `make build`      - Build the HSM CLI/server binary.
- `make test`       - Run all Go tests with verbose output.
- `make clean`      - Clean built binaries and plugins from bin/ and plugins/ directories.

---

## Security Features

- Secure random key generation and cryptographic operations.
- WASM-based isolation for plugin execution.
- Secure memory handling and LMK protection.

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