package plugins

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// PluginManager manages WASM plugin instances.
type PluginManager struct {
	runtime wazero.Runtime
	plugins map[string]*PluginInstance
	mu      sync.RWMutex
}

// PluginInstance holds a WASM module and its execute function.
type PluginInstance struct {
	Module      api.Module
	ExecuteFn   api.Function
	Description string
	mu          sync.Mutex
}

// NewPluginManager initializes a Wazero runtime and returns a PluginManager.
func NewPluginManager(ctx context.Context) *PluginManager {
	return &PluginManager{
		runtime: wazero.NewRuntime(ctx),
		plugins: make(map[string]*PluginInstance),
	}
}

// LoadAll loads all WASM plugins from the specified directory.
func (pm *PluginManager) LoadAll(dir string) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	newPlugins := make(map[string]*PluginInstance)

	for _, f := range files {
		if f.IsDir() || filepath.Ext(f.Name()) != ".wasm" {
			continue
		}

		wasmBytes, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			log.Printf("Failed to read %s: %v", f.Name(), err)
			continue
		}

		compiled, err := pm.runtime.CompileModule(context.Background(), wasmBytes)
		if err != nil {
			log.Printf("Failed to compile %s: %v", f.Name(), err)
			continue
		}

		module, err := pm.runtime.InstantiateModule(
			context.Background(),
			compiled,
			wazero.NewModuleConfig(),
		)
		if err != nil {
			log.Printf("Failed to instantiate %s: %v", f.Name(), err)
			continue
		}

		executeFn := module.ExportedFunction("Execute")
		if executeFn == nil {
			log.Printf("WASM %s does not export Execute", f.Name())
			continue
		}

		cmdCode := strings.TrimSuffix(f.Name(), ".wasm")
		newPlugins[cmdCode] = &PluginInstance{
			Module:      module,
			ExecuteFn:   executeFn,
			Description: cmdCode,
		}
		log.Printf("Loaded WASM plugin: %s", cmdCode)
	}

	pm.mu.Lock()
	pm.plugins = newPlugins
	pm.mu.Unlock()

	return nil
}

// ExecuteCommand executes the given command with input via the corresponding WASM plugin.
func (pm *PluginManager) ExecuteCommand(cmd string, input []byte) ([]byte, error) {
	pm.mu.RLock()
	inst, ok := pm.plugins[cmd]
	pm.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("unknown command")
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()

	// prepare memory and write input at offset 0.
	mem := inst.Module.Memory()
	if len(input) > 0 {
		if !mem.Write(0, input) {
			return nil, fmt.Errorf("failed to write memory")
		}
	}

	// call the Execute function with pointer and length.
	results, err := inst.ExecuteFn.Call(context.Background(), uint64(0), uint64(len(input)))
	if err != nil {
		return nil, fmt.Errorf("plugin execution error: %w", err)
	}
	if len(results) < 2 {
		return nil, fmt.Errorf("invalid plugin response")
	}

	// read output from module memory using returned pointer and length.
	outPtr := uint32(results[0])
	outLen := uint32(results[1])
	data, ok := mem.Read(outPtr, outLen)
	if !ok {
		return nil, fmt.Errorf("failed to read memory")
	}

	return data, nil
}

// GetDescription returns the description of the given command or the command if not found.
func (pm *PluginManager) GetDescription(cmd string) string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	if inst, ok := pm.plugins[cmd]; ok {
		return inst.Description
	}
	return cmd
}
