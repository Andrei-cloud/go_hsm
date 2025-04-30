package plugins

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// PluginManager manages WASM plugin instances and supports hot reload by recreating the runtime.
type PluginManager struct {
	//nolint:containedctx // Context is stored in the struct intentionally to allow reuse across plugin operations.
	ctx     context.Context
	runtime wazero.Runtime
	plugins map[string]*PluginInstance
	mu      sync.RWMutex
}

// PluginInstance holds a WASM module and its execute function.
type PluginInstance struct {
	Module      api.Module
	Alloc       api.Function
	Free        api.Function
	ExecuteFn   api.Function
	Description string
	mu          sync.Mutex
}

// NewPluginManager returns a PluginManager ready to load plugins.
func NewPluginManager(ctx context.Context) *PluginManager {
	return &PluginManager{ctx: ctx, plugins: make(map[string]*PluginInstance)}
}

// LoadAll loads all WASM plugins from the specified directory.
func (pm *PluginManager) LoadAll(dir string) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	// create new runtime for fresh module instantiation.
	newRt := wazero.NewRuntime(pm.ctx)
	wasi_snapshot_preview1.MustInstantiate(pm.ctx, newRt)

	newPlugins := make(map[string]*PluginInstance)

	for _, f := range files {
		if f.IsDir() || filepath.Ext(f.Name()) != ".wasm" {
			continue
		}

		wasmBytes, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			log.Error().Err(err).Str("file", f.Name()).Msg("failed to read plugin file")

			continue
		}

		cmdCode := strings.TrimSuffix(f.Name(), ".wasm")
		compiled, err := newRt.CompileModule(pm.ctx, wasmBytes)
		if err != nil {
			log.Error().Err(err).Str("file", f.Name()).Msg("failed to compile plugin module")
			continue
		}

		// Create module config that disables automatic start function execution
		cfg := wazero.NewModuleConfig().
			WithName(cmdCode).
			WithStartFunctions() // Empty list means don't run any start functions

		module, err := newRt.InstantiateModule(pm.ctx, compiled, cfg)
		if err != nil {
			log.Error().Err(err).Str("file", f.Name()).Msg("failed to instantiate plugin module")

			continue
		}

		executeFn := module.ExportedFunction("Execute")
		if executeFn == nil {
			log.Warn().Str("file", f.Name()).Msg("plugin does not export Execute function")

			continue
		}

		allocFn := module.ExportedFunction("Alloc")
		if allocFn == nil {
			log.Warn().Str("file", f.Name()).Msg("plugin does not export Alloc function")
			continue
		}

		freeFn := module.ExportedFunction("Free")
		if freeFn == nil {
			log.Warn().Str("file", f.Name()).Msg("plugin does not export Free function")
			continue
		}

		newPlugins[cmdCode] = &PluginInstance{
			Module:      module,
			Alloc:       allocFn,
			Free:        freeFn,
			ExecuteFn:   executeFn,
			Description: cmdCode,
		}
		log.Info().Str("plugin", cmdCode).Msg("loaded wasm plugin")
	}

	pm.mu.Lock()
	if pm.runtime != nil {
		if err := pm.runtime.Close(pm.ctx); err != nil {
			log.Error().Err(err).Msg("failed to close previous runtime")
		}
	}
	pm.runtime = newRt
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
		return nil, errors.New("unknown command")
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()

	// allocate guest memory and write input.
	ptr, err := AllocAndWrite(pm.ctx, inst.Module, inst.Alloc, input)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	// execute plugin and get combined result.
	combined, err := CallExecute(pm.ctx, inst.ExecuteFn, ptr, uint32(len(input)))
	if err != nil {
		return nil, fmt.Errorf("plugin execution error: %w", err)
	}

	// unpack result into pointer and length.
	outPtr, outLen := UnpackResult(combined)

	// read response from guest memory.
	resp, err := ReadResult(inst.Module, outPtr, outLen)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	return resp, nil
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

// Context returns the context used by the plugin manager.
func (pm *PluginManager) Context() context.Context {
	return pm.ctx
}

// Close closes the underlying WASM runtime.
func (pm *PluginManager) Close() error {
	return pm.runtime.Close(pm.ctx)
}
