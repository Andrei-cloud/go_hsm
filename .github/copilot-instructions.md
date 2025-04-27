###Coding Rules:
* All coments must end in a period.
* ```return``` and ```continue``` should have an empty line before.
* follow declaration order as: ```const```, ```var```, ```type``` and only after their methods.
* type must not be placed after func (desired order: const,var,type,func)
* error-strings: error strings should not be capitalized or end with punctuation or a newline.
* empty-lines: shoud not be an extra empty line at the start of a block
* use-any: since Go 1.18 'interface{}' can be replaced by 'any' (revive)

#Development Plan for Extendable Go HSM Server with WASM Plugins

##Overview and Objectives

This plan outlines a step-by-step approach to implement an extendable HSM server in Go, using the anet library for TCP server functionality and WebAssembly (WASM) modules as plug-in command handlers. The goal is to create a modular, hot-reloadable system where each HSM command is handled by a WASM plugin conforming to a common interface. The server will respond with a special error code for unknown commands (incrementing the command code and appending 86 as per the requirement). Logging will be handled with zerolog for structured output to stdout, including detailed context (client IP, data in hex, command description, response, error codes, thread counts, etc.). The plan emphasizes clean code structure, extensibility, and clear instructions suitable for implementation (even by AI coding assistants like GitHub Copilot).

###Project Structure and Module Responsibilities

Organize the project into clear folders and packages for maintainability. A possible directory layout is:
```
hsm-server/                   # Root of the project
├── cmd/                      # Main application entry
│   └── hsm-server/main.go    # Initializes server and orchestrates components
├── internal/                 # Internal packages for core logic
│   ├── server/               # TCP server setup (using anet) and request handling
│   ├── plugins/              # WASM plugin loading and invocation logic
│   └── logging/              # Logger initialization and helpers
├── commands/                 # Directory containing WASM plugin files (one per command)
└── go.mod                    # Go module file with dependencies (anet, zerolog, WASM runtime)
```
Each module has a distinct responsibility:
	•	cmd/hsm-server/main.go: Parses config (if any, e.g. JSON like config.json), sets up logging, starts the server, and listens for hot-reload signals.
	•	internal/server: Uses anet to accept and manage TCP connections ￼, implements the message handler that delegates to plugins, and enforces the HSM protocol (framing, response format, unknown command handling).
	•	internal/plugins: Manages loading/unloading of WASM modules from the commands/ folder, provides a common interface for plugins (e.g., an Execute function), and integrates the chosen WASM runtime (e.g. Wazero) to call into the WASM code.
	•	internal/logging: Sets up the zerolog logger with appropriate formatting (structured JSON to stdout) and provides helper functions to log events with consistent fields (connection info, command, data hex, etc.).

This separation ensures code is modular and extensible – new functionality (like additional logging or alternative transports) can be added without breaking other components. It also allows focusing on one aspect at a time, which helps AI-based coding agents follow the plan module by module.

###Technology Choices and Dependencies

1. Networking (TCP Server via anet): We will use the anet package for handling TCP connections and message framing. anet provides an embeddable framework to accept and process framed messages over TCP ￼. It includes a Server with configurable timeouts and a Handler interface for processing messages ￼. By using anet, we get robust connection pooling, a standardized message length prefix protocol, and graceful shutdown out-of-the-box, so we can focus on implementing our HSM-specific logic.

2. WASM Runtime (plugin execution): Among available Go WASM runtimes (e.g. Wazero, Wasmer, Wasmtime), we recommend using Wazero for this project. Wazero is a pure Go WebAssembly runtime with zero external dependencies and no CGO requirements ￼ ￼. This makes it easy to embed, portable across platforms, and safe to use concurrently in Go programs. Wazero is well-documented and optimized for Go use cases, providing idiomatic APIs to instantiate modules and call exported functions. In contrast, alternatives like Wasmer or Wasmtime rely on CGO or external engines, which complicate deployment and cross-compilation. Using Wazero will simplify integration and keep the build process straightforward. (We will include Wazero via Go modules, e.g. import "github.com/tetratelabs/wazero".)

3. Logging (zerolog): We choose zerolog for structured logging. Zerolog allows logging messages in JSON format with key-value pairs and timestamps, which is ideal for the detailed, structured logs we need. It is high-performance and writes logs to stdout with minimal overhead. We will log events such as connections, requests, and responses at appropriate levels (e.g. info for normal operations, error for failures). The output format will include fields like client IP, command code, descriptions, hex-encoded data, response code, error codes, and active thread counts, formatted as JSON by zerolog (or a human-friendly console output if configured). This consistent format makes it easier to parse logs or feed them into monitoring systems, and matches the example structure the user provided (e.g., a JSON object containing all relevant details per event).

4. Hot Reload (OS Signal): The Go standard library will be used to capture a specific OS signal (e.g. SIGHUP) to trigger hot-reloading of WASM plugins. This avoids downtime: when the signal is received, the server will refresh all command handlers by reloading the WASM files from disk. We will ensure this mechanism works on Unix-like systems (note: Windows does not support SIGHUP, but we can document that limitation or use an alternative trigger on Windows if needed). The choice of SIGHUP is conventional for “reload config” behavior in servers, and won’t terminate the process like SIGINT/TERM. The implementation will use os/signal.Notify to catch the signal asynchronously.

Dependencies Summary: Add the following to go.mod:
	•	github.com/Andrei-cloud/anet (for TCP server) – this provides anet.Server and related utilities.
	•	github.com/rs/zerolog (for logging).
	•	github.com/tetratelabs/wazero (for WASM runtime) – or another chosen runtime; here we proceed with Wazero for reasons above.
	•	(If needed, golang.org/x/sys for signal constants like syscall.SIGHUP.)

After setting up the module (go mod init hsm-server), run go get for these dependencies. This ensures our project is ready to import and use these libraries in code.

####Step 1: Logger Initialization (Structured Logging Setup)

Before starting the server, configure the logger so that all components can use it. In internal/logging/logging.go, create a function to initialize zerolog:
```go
package logging

import (
    "github.com/rs/zerolog"
    "github.com/rs/zerolog/log"
    "os"
)

func InitLogger(debug bool) {
    // Log to stdout, and set time format and level
    zerolog.TimeFieldFormat = zerolog.TimeFormatUnix   // use Unix timestamp or RFC3339 as needed
    log.Logger = zerolog.New(os.Stdout).With().Timestamp().Logger()
    if debug {
        // Human-readable console output (for development) or set global level to debug
        log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
        zerolog.SetGlobalLevel(zerolog.DebugLevel)
    } else {
        zerolog.SetGlobalLevel(zerolog.InfoLevel)
    }
}
```
Key points for logging setup:
	•	Structured Fields: We will log messages with fields such as "client_ip", "event", "command", "description", "request_hex", "response_hex", "response_command", "error_code", "active_connections", etc. Using zerolog, we can chain field additions, e.g. log.Info().Str("client_ip", ip).Int("active_connections", count)...Msg("received command"). This results in a log entry as a JSON object with those keys.
	•	Standard Output: All logs are written to stdout (the default for zerolog). This aligns with container logging best practices and the requirement to print logs to stdout.
	•	Level Control: In production, use Info level by default; we can allow a debug mode via config or an environment variable to include more verbose logs (zerolog will filter by global level).
	•	Example Log Entry: When a request is processed, an info log might look like (as JSON):
```json
{
  "level": "info",
  "time": "2025-04-27T11:31:59Z",
  "event": "command_processed",
  "client_ip": "192.168.1.100:53000",
  "command": "NC",
  "description": "Generate Key", 
  "request_hex": "4e 43 01 02 03", 
  "response_hex": "4e 44 8 6", 
  "response_command": "ND", 
  "error_code": 86, 
  "active_connections": 3
}
```
(The above illustrates the content; actual formatting might be all in one line for JSON. Here request_hex and response_hex show byte values in hex form separated by spaces; 4e43 is “NC” in ASCII, and 4e44 3836 corresponds to “ND86”.)

We will create helper functions in the logging package for common events. For example, a function LogRequest(conn net.Addr, cmd string, description string, reqData []byte) can format and output a log for a received command, and LogResponse(conn net.Addr, cmd string, respData []byte, errCode int) for the response. This encapsulation ensures consistent field usage. AI agents can directly use these helpers to log events without forgetting any required field.

####Step 2: Define the WASM Plugin Interface

We need a common interface that all WASM-based command handlers implement so the server can invoke them uniformly. We define this interface in Go (host side) and also establish the expected WASM exports that plugins must provide:

```go // internal/plugins/interface.go
package plugins

// HSMCommand defines the behavior of a WASM plugin command handler
type HSMCommand interface {
    Execute(input []byte) ([]byte, error)
    // (Optional: could add a Method to get command description or name if needed)
}
```
Each WASM module (plugin) will correspond to one command and implement the equivalent of Execute. In practice, since the plugin is compiled to WASM, it cannot implement a Go interface directly; instead, it will export a known function that the host will call. We will require every WASM module to export a function with a consistent name and signature, for example:
	•	Exported function name: Execute (or ProcessCommand, etc., but we’ll use Execute for clarity).
	•	Signature: The function takes as input the request bytes and returns the response bytes (and possibly an error indicator). In WebAssembly, this will likely be represented through pointers/lengths in linear memory or via WASI I/O.

For simplicity, we can decide that the plugin’s Execute function will operate on a byte buffer passed in and produce a byte buffer as output. With Wazero, one approach is:
	•	The host will provide the input data by writing it to the module’s memory (or by calling an imported function if the plugin uses WASI for input).
	•	Then call the Execute exported function, which processes the input from memory and writes the output to memory.
	•	The function returns a pointer/length or writes to a known memory region that the host can read back.

Design Decision: We will standardize the plugin to use an export Execute(ptr, len) -> (respPtr, respLen) in WASM. However, implementing this fully may require additional glue (like an export for memory or an allocator). For the scope of our plan, we assume the use of Wazero’s API to simplify calling: we can use Wazero’s ability to call Go functions exported to WASM or vice versa. Another approach is to compile plugins with the WASI interface and use stdin/stdout for passing data, but that adds overhead. We prefer direct function calls for performance.

Plugin Responsibilities: The plugin code (which could be written in Go and compiled to .wasm using TinyGo or GOOS=wasip1 GOARCH=wasm) should:
	•	Export the Execute function as described.
	•	Parse the input bytes according to its command’s protocol.
	•	Perform the required operation (e.g., cryptographic function or data lookup).
	•	Formulate the response bytes. Important: The response should include the proper response command code and any error/status codes. Typically, for a known command, the plugin would append a status code 00 for success or some relevant error code for domain-specific errors. (The host will only override this for the case of an unknown command, using 86 as error code.)
	•	The plugin can optionally include an export or constant for a human-readable command description (for logging). If desired, we might require a secondary export like GetDescription() -> pointer/len returning a string, or simply maintain a map of command descriptions on the host side.

By defining this interface clearly, we ensure all plugins follow the same pattern. This makes adding new commands as simple as dropping a new .wasm file in the directory and reloading – no host code changes needed except perhaps adding a description in a map.

####Step 3: Implement Plugin Manager (Loading WASM Modules)

We will create a component in internal/plugins that handles loading all WASM files from the commands/ directory and managing them at runtime.

3.a. WASM Runtime Initialization

In internal/plugins/manager.go, set up the Wazero runtime and a structure to hold loaded plugins:
```go
package plugins

import (
    "context"
    "os"
    "github.com/tetratelabs/wazero"
    "github.com/tetratelabs/wazero/api"
    // other imports...
)

type PluginManager struct {
    runtime wazero.Runtime
    plugins map[string]*PluginInstance  // map command code -> loaded plugin
}

type PluginInstance struct {
    Module wazero.Module       // The instantiated WASM module
    ExecuteFn api.Function     // Compiled function for Execute
    // We can store command description or other metadata here as well
    Description string
}

// NewPluginManager initializes a Wazero runtime and returns a manager.
func NewPluginManager(ctx context.Context) *PluginManager {
    pm := &PluginManager{
        runtime: wazero.NewRuntime(ctx),
        plugins: make(map[string]*PluginInstance),
    }
    // If plugins require WASI (for standard library support), instantiate it:
    // wasi_snapshot_preview1.MustInstantiate(ctx, pm.runtime)
    return pm
}
```
We use wazero.NewRuntime() to create a fresh WebAssembly runtime environment in which we will load our modules. Wazero being pure Go means this is lightweight and safe to use concurrently ￼. If any plugin expects WASI functions (like printing to stdout or using malloc from WASI), we would instantiate the WASI module as shown (commented out above). For our case, plugins likely won’t need full WASI, unless they are compiled in a way that expects it – we’ll note to ensure plugins are compiled accordingly (e.g. using TinyGo or setting the environment to WASI, and implementing our interface).

3.b. Loading All Plugins from Directory

Implement a method LoadAll(directory string) on PluginManager to load or reload plugins. This will:
	•	Scan the given commands/ directory for .wasm files.
	•	For each file, determine the command code name. We can use the filename (without extension) as the command identifier (e.g. NC.wasm corresponds to command "NC"). This convention means adding a new command is as simple as placing a new WASM with the correct name.
	•	Compile and instantiate the WASM module using Wazero. Use a context with timeout if desired (to avoid hanging on a bad module). For example:
```go
func (pm *PluginManager) LoadAll(dir string) error {
    files, err := os.ReadDir(dir)
    if err != nil {
        return err
    }
    newPlugins := make(map[string]*PluginInstance)

    for _, f := range files {
        if f.IsDir() || filepath.Ext(f.Name()) != ".wasm" {
            continue // skip non-wasm files
        }
        modBytes, err := os.ReadFile(filepath.Join(dir, f.Name()))
        if err != nil {
            log.Error().Err(err).Msgf("Failed to read %s", f.Name())
            continue
        }
        // Compile and instantiate module
        module, err := pm.runtime.Instantiate(context.Background(), modBytes)
        if err != nil {
            log.Error().Err(err).Msgf("Failed to instantiate %s", f.Name())
            continue
        }
        executeFn := module.ExportedFunction("Execute")
        if executeFn == nil {
            log.Error().Msgf("WASM %s does not export an Execute function", f.Name())
            continue
        }
        cmdCode := strings.TrimSuffix(f.Name(), ".wasm")
        // Optionally, retrieve a description if module provides one
        desc := cmdCode
        if descFn := module.ExportedFunction("GetDescription"); descFn != nil {
            // call descFn and read string from memory, omitted for brevity
        }
        newPlugins[cmdCode] = &PluginInstance{Module: module, ExecuteFn: executeFn, Description: desc}
        log.Info().Str("command", cmdCode).Msg("Loaded WASM plugin")
    }

    // Replace old plugins map atomically (to allow hot-swap)
    pm.plugins = newPlugins
    return nil
}
```
A few best practices in this loading logic:
	•	We load everything into a new map first, and then swap it in once fully loaded, to avoid leaving the system in a partially updated state on reload. This also allows the old plugins (if any) to remain serving until the new ones are ready. After swap, we can optionally close the old WASM modules to free memory (Wazero’s runtime can drop modules by closing them or by simply discarding the old runtime if we created a fresh one – another strategy is to instantiate a new wazero.Runtime on each reload, then swap the entire runtime reference, but that requires updating references; for simplicity, reusing one runtime is fine as long as we manage modules).
	•	We log success or failure for each plugin file. An unsuccessful plugin load should not stop the others from loading – we simply skip that plugin (with an error log). The server will treat missing ones as unknown commands at runtime.
	•	We store the compiled Execute function in PluginInstance.ExecuteFn for quick calls on each request. This api.Function can be invoked with executeFn.Call(ctx, params...) to run the WASM code.
	•	Command Descriptions: We attempt to get a human-friendly description. If the plugin exports a GetDescription function (or maybe a global string), we can call it here once to retrieve the description text for logging. (For example, if GetDescription() returns a pointer and length in memory, we’d use Wazero’s memory API to read it into a Go string). If not provided, we default to using the command code itself or have a pre-defined map of descriptions for known commands. This ensures our logs can show "description": "Generate Key" instead of just "NC".

With this LoadAll method, the initial plugin loading can be done in the main.go before starting the server, and the reload can reuse it.

3.c. Plugin Execution Helper

We will add a method to PluginManager to execute a command via the appropriate WASM plugin:
```go
func (pm *PluginManager) ExecuteCommand(cmd string, input []byte) ([]byte, error) {
    plugin, exists := pm.plugins[cmd]
    if !exists {
        return nil, fmt.Errorf("unknown command")
    }
    // Prepare input for WASM call
    // e.g., allocate memory and write input (if needed)
    // For simplicity, assume function signature is Execute(offset, length) -> (resultOffset, resultLength)
    // We'll need to get module memory to interact with it:
    mem := plugin.Module.Memory()  // using wazero API to get linear memory
    // Allocate input in memory (this might require calling a WASM allocator or using a fixed memory offset)
    // ... (implementation detail)
    // For now, assume input is small and we copy directly at offset 0 of memory.
    if len(input) > 0 {
        mem.Write(context.Background(), 0, input)  // write input bytes at memory offset 0
    }
    // Call WASM Execute function with parameters (offset=0, length=len(input))
    res, err := plugin.ExecuteFn.Call(context.Background(), 0, uint64(len(input)))
    if err != nil {
        return nil, fmt.Errorf("plugin execution error: %w", err)
    }
    // The WASM function is expected to return the pointer and length of the output in memory.
    if len(res) < 2 {
        return nil, fmt.Errorf("invalid response from plugin")
    }
    outPtr := uint32(res[0])        // assuming 32-bit pointer
    outLen := uint32(res[1])
    output := make([]byte, outLen)
    mem.Read(context.Background(), outPtr, output)
    return output, nil
}
```
The above is pseudo-code to illustrate the steps. Real implementation may depend on how the plugin was written to handle memory. We may need the plugin to provide an alloc function to allocate memory for input/output if not using a pre-defined memory region. Alternatively, we could call the WASM function with a pre-allocated buffer. This is a critical integration detail – to keep our plan high-level, we assume we manage to pass input and get output as shown (developers should adjust according to the chosen WASM compilation strategy).

Error Handling in Execution: If the plugin returns an error or traps (e.g., panics or violates memory), executeFn.Call will return a non-nil error. We will catch that and handle it by returning an error to the caller (the server handler). The server can then decide how to respond to the client (likely with an error code). We’ll cover that in the message handling section.

Step 4: TCP Server Setup with anet

Now, we implement the networking portion using the anet library. The anet.Server will handle incoming client connections, manage timeouts, and call our handler for each message. Steps to set up the server:

4.a. Configure Server Parameters

We create a server configuration struct from anet. For example (based on anet documentation and code):
```go
import "github.com/Andrei-cloud/anet/server"

cfg := server.ServerConfig{
    Address:          "0.0.0.0:9999",   // Listen address and port
    MaxConns:         100,             // Maximum simultaneous connections
    ReadTimeout:      30 * time.Second,
    WriteTimeout:     30 * time.Second,
    IdleTimeout:      60 * time.Second,
    ShutdownTimeout:  5 * time.Second,
    KeepAliveInterval: 30 * time.Second,
}
srv := server.NewServer(cfg)
```
These parameters can also be loaded from config.json (which might contain tunable values). The defaults above are sane, but we can expose them in the config.json for easy tweaking. The ServerConfig corresponds to fields like keep-alive and timeouts mentioned in anet’s README ￼. We ensure the server is set to gracefully shutdown within ShutdownTimeout to avoid hanging on exit.

4.b. Implement the Message Handler

anet uses a Handler interface for processing incoming messages on the server ￼. We will implement this interface to integrate with our plugin manager. The Handler likely looks similar to func Handle(conn net.Conn, data []byte) []byte or uses a context object. For our plan, we’ll assume a simple signature where our handler function receives the request bytes and returns the response bytes (and maybe an error for logging).

We will implement an adapter so that our handler can be a closure or struct method capturing our PluginManager and logging component. For example:
```go
type HSMHandler struct {
    PluginMgr *plugins.PluginManager
}

func (h *HSMHandler) HandleMessage(clientAddr net.Addr, request []byte) ([]byte, error) {
    // 1. Parse command code from request
    if len(request) < 2 {
        log.Error().Msg("Received malformed request (too short)")
        return nil, fmt.Errorf("malformed request")
    }
    cmdCode := string(request[:2])  // assuming command code is first 2 bytes (ASCII letters)
    // 2. Log the incoming request details
    hexReq := fmt.Sprintf("%X", request)  // hex string of request bytes
    desc := h.PluginMgr.GetDescription(cmdCode)  // get description if available
    activeConns := currentActiveConnections()    // function to get active connection count
    log.Info().
        Str("event", "request_received").
        Str("client_ip", clientAddr.String()).
        Str("command", cmdCode).
        Str("description", desc).
        Str("request_hex", hexReq).
        Int("active_connections", activeConns).
        Msg("Received command")

    // 3. Determine appropriate action
    output, err := h.PluginMgr.ExecuteCommand(cmdCode, request)
    if err != nil {
        // Plugin not found or execution error
        var respCmd string
        var errCode string
        if err.Error() == "unknown command" {
            // Command not loaded in plugins
            respCmd = incrementCommandCode(cmdCode)
            errCode = "86"
            log.Warn().
                Str("event", "unknown_command").
                Str("client_ip", clientAddr.String()).
                Str("command", cmdCode).
                Msgf("Command not recognized, responding with %s%v", respCmd, errCode)
        } else {
            // Plugin existed but failed during execution
            respCmd = incrementCommandCode(cmdCode)
            errCode = "86"  // we could define a different code for internal error, but using 86 for simplicity
            log.Error().
                Str("event", "plugin_error").
                Str("client_ip", clientAddr.String()).
                Str("command", cmdCode).
                Err(err).
                Msgf("Plugin execution failed, responding with %s%v", respCmd, errCode)
        }
        // Formulate error response: e.g. "ND86"
        respBytes := []byte(respCmd + errCode)
        hexResp := fmt.Sprintf("%X", respBytes)
        log.Info().
            Str("event", "response_sent").
            Str("client_ip", clientAddr.String()).
            Str("command", cmdCode).
            Str("response_command", respCmd).
            Str("response_hex", hexResp).
            Int("error_code", 86).
            Int("active_connections", activeConns).
            Msg("Responded with error code")
        return respBytes, nil  // returning response with error code
    }

    // 4. Successful execution, plugin returned output bytes
    // Log the response details
    respCmdCode := string(output[:2]) // assuming plugin's output also starts with response command code
    // Possibly the plugin includes its own status code at end (like "00" for success).
    var errCode int
    if len(output) >= 4 {
        // If last two bytes are digits, interpret as error code
        errStr := string(output[len(output)-2:])
        if n, e := strconv.Atoi(errStr); e == nil {
            errCode = n
        }
    }
    hexResp := fmt.Sprintf("%X", output)
    log.Info().
        Str("event", "response_sent").
        Str("client_ip", clientAddr.String()).
        Str("command", cmdCode).
        Str("response_command", respCmdCode).
        Str("response_hex", hexResp).
        Int("error_code", errCode).
        Int("active_connections", activeConns).
        Msg("Processed command successfully")
    return output, nil
}
```
In the pseudocode above, we demonstrate:
	•	Extracting the command identifier (assuming a 2-byte code at the start of the message, as the example “NC” suggests).
	•	Logging the received request with all required details. The currentActiveConnections() would be a helper that returns the number of ongoing connections (see Step 5 for maintaining this count).
	•	Using PluginManager.ExecuteCommand to attempt to run the plugin. If it returns an error indicating the command was not found, we handle it as an unknown command. If it returns an execution error, we treat it similarly (possibly could differentiate error codes, but the requirement only specifies 86 for unknown). In both cases, we increment the last letter of the command to form the response command code and append “86”. For example, if cmdCode = "NC", incrementCommandCode("NC") should yield "ND" (we will implement this helper carefully, handling cases like “NZ” -> “NA” with carry if needed, though HSM commands might not use all letter ranges).
	•	Constructing the error response bytes (as ASCII). “ND86” in bytes is []byte{'N','D','8','6'}. We log that we responded with an error. Notice we log at warn level for an unknown command event (since it’s not an error in our system, but a client sent an unknown code) and at error for plugin execution failures (since that indicates a bug or issue in the plugin). The actual sending of the response is handled by returning the bytes from the handler (the anet server will send it back to the client).
	•	If the plugin execution was successful, we expect it returned the full response message (including the response command and status code). We log the response similarly, including the response command (likely original command’s first letter and second letter incremented if following HSM conventions) and an error code (if the plugin appended one, typically 00 for success). We parse the error code by reading the last two characters of the response if they are digits. (This may vary if the plugin uses a binary format; adjust accordingly. For a typical HSM ASCII protocol, commands and codes are textual.)
	•	Finally, return the output bytes to be sent to the client.

The Handler ensures no partial writes or disconnection issues are treated incorrectly: if the handler returns an error (non-nil error), anet may close the connection or attempt a retry depending on implementation. Our design chooses to return a valid error response to the client even in error cases, and return nil error back to anet (since we handled the error by sending a response). Only truly unrecoverable conditions (like malformed request) might result in returning an error to anet to possibly close the connection.

We’ll integrate this handler with anet by registering it when starting the server:
```go
h := &HSMHandler{PluginMgr: pluginManager}
if err := srv.Start(h); err != nil {
    log.Fatal().Err(err).Msg("Failed to start server")
}
```
(Actual anet usage may differ; if srv.Start signature is different, adapt accordingly. Possibly anet provides something like server.ListenAndServe(handler).)

Step 5: Manage Connections and Concurrency

The server will handle multiple clients concurrently. We must ensure thread safety and resource management:
	•	Connection Counting: Maintain an atomic counter or use anet hooks to know how many connections are active. We can increment the counter each time a new connection is accepted and decrement when closed. If anet.Server doesn’t directly provide callback for onConnect/onDisconnect, we can wrap the net.Listener or manage a global sync.WaitGroup or counter updated in the handler (less ideal because a handler might handle multiple messages on one connection). Instead, a better approach is to utilize the server’s connection lifecycle events if available. If not, we might increment the counter when a handler first runs for a new connection (and ensure to only increment once per connection). For simplicity, treat each connected socket as incrementing on first message and decrement on disconnect (we can detect disconnect if handler returns an error or if anet signals it).
We will implement a small struct in HSMHandler or in the server package to track this. For instance, we could embed our HSMHandler in another struct that also implements server.ConnHandler if anet expects that for connection events.
	•	Goroutine Safety for PluginManager: Accessing the PluginManager.plugins map must be safe under concurrent use. We will protect the map with a sync.RWMutex or leverage the fact we swap the whole map atomically. In the loading code, we replaced the map in one operation (pm.plugins = newMap) – in Go, assigning a map reference is atomic, but to be extra safe we might want a lock or to use atomic.Value for the plugins map. A simple solution: use a RWMutex where all reads (ExecuteCommand calls) take an RLock, and the reload (LoadAll) takes a Lock. Given plugin execution might be frequent, a RWMutex is suitable. We should include this in PluginManager: a sync.RWMutex mu around access to pm.plugins.
	•	In ExecuteCommand, do pm.mu.RLock() and defer pm.mu.RUnlock().
	•	In LoadAll, do pm.mu.Lock() when swapping in the new map, then pm.mu.Unlock().
This ensures no race conditions if a reload signal comes while requests are in flight. The trade-off is minimal performance overhead but high safety.
	•	Concurrency and WASM: We should consider whether multiple executions of the same WASM module can happen concurrently. If two clients send the same command at roughly the same time, our server will attempt to call the same plugin’s ExecuteFn concurrently in separate goroutines. We must know if Wazero’s api.Function.Call is goroutine-safe. According to Wazero docs, multiple modules can be run in parallel, but a single module’s state (especially memory) might not support concurrent calls unless the module was designed for it (no shared mutable state or reentrant).
	•	Simplest safe route: serialize calls per module. We can put a mutex in each PluginInstance to ensure its ExecuteFn.Call is not invoked concurrently. This can be as easy as PluginInstance.mu sync.Mutex and lock around the call. HSM commands are often CPU-bound but quick, so serializing per command should be fine. Different commands (different modules) can still run in parallel on different goroutines.
	•	Alternatively, instantiate separate module instances for each connection or each request. This is heavier on resources. Wazero allows multiple instantiations of the same compiled module. We could compile a module once and instantiating it for each new connection if we wanted isolation. However, given the likely low volume of simultaneous identical HSM operations, a single instance with a call mutex is acceptable and simpler.

By handling concurrency carefully, we ensure the server can handle multiple requests simultaneously without data races or inconsistent behavior.

Step 6: Hot-Reload Mechanism (Reloading WASM Commands on Signal)

Implementing hot-reload allows updating or adding command handlers without stopping the server. Here’s how to achieve it:

6.a. Signal Listener

In main.go, after starting the server, set up a goroutine to listen for a specific OS signal:
```go
import (
    "os/signal"
    "syscall"
)

// ... after server startup:
reloadChan := make(chan os.Signal, 1)
signal.Notify(reloadChan, syscall.SIGHUP)  // Listen for SIGHUP
go func() {
    for {
        <-reloadChan  // block until signal received
        log.Info().Msg("SIGHUP received: reloading WASM command modules")
        err := pluginManager.LoadAll("commands")
        if err != nil {
            log.Error().Err(err).Msg("Reload failed")
        } else {
            log.Info().Msg("WASM modules reloaded successfully")
        }
    }
}()
```
We use a separate goroutine so the main thread can continue handling the server. When SIGHUP is caught:
	•	Log that reload is starting.
	•	Call our pluginManager.LoadAll to refresh the plugins map (this will instantiate any new modules and replace the map in a thread-safe manner as discussed).
	•	Log success or failure. If there’s an error (e.g., directory not found or a bad module), we keep the old plugins map intact (since we only swap on success). The log will help diagnose issues.
	•	The loop allows multiple HUP signals to be handled (the channel ensures we handle one at a time if signals come in bursts).

Windows note: On Windows, SIGHUP is not available. If cross-platform support is needed, we could use a different trigger (like listening on a local TCP/Unix socket or using a file watcher) but given the requirement, we assume a Unix-like environment for simplicity.

6.b. Plugin Resource Cleanup

Optionally, on reload we might want to unload or free the old WASM modules to reclaim memory. Wazero might not yet have a full API for unloading individual modules, but dropping references and possibly calling module.Close() (if available) could free memory. An alternative approach is to create a new wazero.Runtime on each reload (via NewPluginManager), then swap the entire PluginManager in one go. For example:
	•	On SIGHUP, create newPM := NewPluginManager(), call newPM.LoadAll(...), then swap pluginManager = newPM (with proper locking while swapping references in the handler).
	•	Then call oldPM.runtime.Close() to free all old modules in one go.

This approach ensures no leaks. But to keep it simple, we can skip this level of detail; it can be an enhancement. Our plan will work with reusing the runtime as well, since we overwrite the map and reinstantiate modules (which loads new code for updated files; note, if a file hasn’t changed, currently our LoadAll logic will still reload it fresh – we could optimize to skip reloading unchanged files, but it’s unnecessary complexity given the reload is manual trigger).

6.c. During Reload Considerations

While the reload is happening, requests might still be coming in. With our locking strategy, pm.LoadAll acquires a write lock on the plugins map. This will block new requests in ExecuteCommand until loading is done, which is fine. The reload should be quick (loading a handful of WASM files). To the clients, there might be a slight pause in processing at that moment, but no downtime. Ongoing executions will complete using the old plugins if they already fetched them before the lock (or if we replaced the map after, subsequent calls use new ones). We ensure to perform the swap instantly after loading all, to minimize inconsistency. Logging will note exactly when reload happened.

Step 7: Error Handling and Validation

Robust error handling ensures the server remains stable and clients get meaningful responses:
	•	Unknown Command: As specified, if a command is not found among loaded plugins, we respond with the command code incremented by one and error code 86. We will implement incrementCommandCode(cmd string) string to handle this. For example:
```go
func incrementCommandCode(cmd string) string {
    if len(cmd) == 0 { return cmd }
    // Assuming command code is two uppercase letters [A-Z]
    lastChar := cmd[len(cmd)-1]
    if lastChar == 'Z' {
        // wrap around Z->A (and potentially carry to previous char if needed)
        // e.g., AZ -> AA (though HSM commands might not reach this scenario)
        return cmd[:len(cmd)-1] + "A"
    }
    // increment last character
    incChar := lastChar + 1
    return cmd[:len(cmd)-1] + string(incChar)
}
```
This simple logic handles alphabetic increment. We assume commands are alphabetical. (If commands can have digits and letters, a more complex increment might be needed, but the example suggests letter codes). The first letter is left unchanged, only the second letter increments, per example NC -> ND.
The error code 86 will be appended as two characters. We interpret this as an ASCII representation of the numeric error code 86 (which in an HSM context likely means “unknown command”). We should clarify that the protocol expects error codes as two-digit strings in responses. We will follow that pattern.

	•	Plugin Execution Errors: If a plugin exists but fails (e.g., due to an exception, trap, or returns an invalid output), we will handle it similarly to unknown. In the plan above, we decided to respond with <incCmd>86 for any such failure as well, logging it as a server-side error. In a real HSM, there might be distinct error codes for “execution error” vs “unknown command”, but without specifics we reuse 86 for all unhandled errors. This can be refined if needed (for example, use 90 for internal errors).
We make sure to catch panics or unexpected conditions too. The ExecuteCommand will catch errors thrown by the WASM runtime (like out-of bounds memory access resulting in a trap). Additionally, we can recover from any panic in our handler to avoid crashing the server: wrapping the main handler logic in a defer func(){ if r := recover(); r != nil { log.Error().Msgf("Recovered panic: %v", r) ... } } and responding with a generic error to client.
	•	Malformed Requests: If a client sends data shorter than expected (e.g., less than 2 bytes so no command code), we consider it malformed. We logged an error for “malformed request” and returned an error from handler. anet should then close that connection (assuming it treats a handler error as a reason to drop the client). Alternatively, we could respond with some generic error message. But since the protocol isn’t defined for that, it’s safer to just drop the connection or ignore. We’ll opt to log and close.
	•	Graceful Shutdown: If the server is shutting down (e.g., on SIGINT), anet provides Server.Stop() for graceful shutdown ￼. We should catch SIGINT/SIGTERM similarly via os/signal and call srv.Stop() allowing it to close connections cleanly within ShutdownTimeout. This ensures no message is cut off mid-processing.
	•	Logging on Errors: We already integrate logging in each error scenario (unknown command -> warn, plugin error -> error, etc.). This is crucial for debugging in production. Each log includes context of what happened and what we did (responded with ND86, etc.). For example, on an unknown command “NC”, log might show:

```json 
{ "level": "warn", "event": "unknown_command", "client_ip": "...", "command": "NC", "msg": "Command not recognized, responding with ND86" }
```

followed by an info log for the response:

```json
{ "level": "info", "event": "response_sent", "command": "NC", "response_command": "ND", "error_code": 86, ... }
```

Using structured logs means we can easily filter by "event":"unknown_command" or by error_code.

	•	Validation: If certain commands expect specific lengths or formats of data, the plugin should handle that and perhaps return an error code (different from 86) indicating invalid parameter. We might include some basic validation on the server side too if needed (for instance, if we know a command must have at least X bytes in the request, we can check and directly respond with an error). However, it might be better to let each plugin validate its input since it knows the format. The server will primarily ensure the overall framing is correct (which anet does by providing full message based on length prefix).

Step 8: Testing and Example Scenario

Once implemented, test the system with a variety of scenarios to ensure everything works as intended:
	•	Normal Command Execution: Create a simple test WASM plugin for a fake command (say NC.wasm) that echoes back some data with ND00. Run the server, send an NC command from a TCP client, and verify the server logs the request, calls the plugin, and the client receives ND00 (meaning success, error code 00). Confirm the logs show response_command: ND and error_code: 0. Also check that active_connections increments when the client connects and decrements on disconnect.
	•	Unknown Command: Send a command that doesn’t exist as a plugin, e.g. ZZ. The server should respond with ZA86 (assuming Z+1 wraps to A) or if we only increment second letter, Z[+1]86 (if second letter isn’t Z). Check the client receives that and logs show the appropriate warnings.
	•	Hot Reload: Add or modify a WASM plugin file while the server is running. Trigger SIGHUP (on Linux, kill -HUP <pid>). See that the server logs “WASM modules reloaded”. Then send a command for the newly added plugin to ensure it’s now recognized. This test verifies that the loading mechanism and map swapping works.
	•	Concurrent Requests: Use a tool or a test to simulate multiple clients connecting and sending commands at once (especially to the same command). Verify that all responses are correct and no race conditions occur (for example, no mixed up responses). If performance allows, test that the latency is acceptable; if using mutex per plugin, concurrent different commands should scale linearly.
	•	Error in Plugin: Modify a plugin to deliberately cause an error (e.g., divide by zero or panic). Recompile to WASM and reload. Then send that command. The server should catch the trap, log an error about plugin failure, and respond with the <incCmd>86 error response, rather than crash. This ensures our error handling in ExecuteCommand is effective.

Step 9: Best Practices and Future Extensibility

To maintain a high-quality codebase, follow these best practices during development:
	•	Code Style and Clarity: Use clear naming for functions and variables (as exemplified above). Group related logic into small, testable functions (e.g., one function to formulate response bytes, one for incrementing command codes, etc.). This makes it easier for others or AI tools to navigate the code. Include comments describing non-obvious logic (like memory handling for WASM calls).
	•	Modularity: The separation of concerns we outlined (server vs plugin manager vs logging) should be reflected in code. Avoid global state as much as possible; where needed (like a global plugin manager or logger), pass references explicitly or use singletons sparingly. This modular approach makes it easier to replace components. For example, one could swap out anet with a different TCP library if needed, or replace the WASM runtime without touching the server logic.
	•	Extending Commands: To add a new HSM command, a developer should create a new WASM module implementing the Execute interface for that command and place it in commands/. They should also add a descriptive name for logging (either in the plugin via GetDescription or in a host-side map). No changes to the server code should be required. The hot-reload feature will pick up the new module. Document this workflow for future developers.
	•	Plugin Development Guidelines: Provide guidance for writing the WASM plugins. For example, if using TinyGo:
	•	Show an example plugin code, perhaps using TinyGo’s //export Execute to define the function, reading from memory and writing a response.
	•	Instruct how to compile it: tinygo build -o NC.wasm -target=wasi ./cmd_nc_plugin.go (if using WASI target), or regular Go: GOOS=wasip1 GOARCH=wasm go build -o NC.wasm ./cmd_nc_plugin.go (ensuring the code uses a proper entrypoint).
	•	Make sure plugin developers know to output error codes as two-digit strings and follow the protocol format.
	•	Performance Considerations: While WASM adds overhead compared to native function calls, it provides isolation and flexibility. If performance becomes an issue for a specific high-frequency command, consider implementing that command directly in Go as an internal handler (bypassing WASM) while keeping others as WASM. The architecture can allow this by checking a built-in commands map first, then falling back to WASM plugins. This is an extensibility point (not needed initially, but good to keep in mind).
	•	Security: Running untrusted code in WASM is safer than running native plugins, but still be mindful. Wazero sandboxes execution, but plugins could consume CPU or memory. Use context timeouts if needed when calling ExecuteFn.Call (Wazero supports context cancellation to stop long-running WASM). Also consider limiting memory by configuring the runtime or modules (e.g., set max memory/pages). Log or monitor if any plugin consistently fails or behaves oddly.
	•	Thread and Memory Management: We already plan to avoid data races with locks. We should also ensure there are no memory leaks: e.g., if we keep instantiating modules on reload without freeing, memory will grow. We addressed this by possibly replacing the entire runtime or closing modules. Regular restarts of the server could be a fallback, but since hot-reload is a feature, better to manage explicitly. We should test reload repeatedly to see if memory usage stabilizes.

By adhering to these practices, the resulting code will be maintainable and easier to extend. The plan as detailed above can be handed to a development team or an AI code assistant to implement step-by-step. Each section corresponds to concrete code tasks:
	1.	Initialize logger,
	2.	Setup plugin interface and loader,
	3.	Integrate WASM runtime,
	4.	Build the server with anet and handler,
	5.	Implement hot-reload via signal,
	6.	Add logging in each critical path,
	7.	Handle errors and test thoroughly.

Following this blueprint will yield a robust extendable HSM server that meets all the requirements. The structured approach ensures that even an AI agent like Copilot can generate the code in parts, verify against the plan, and produce a correct implementation.