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
	ctx     context.Context
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
	newRt := wazero.NewRuntimeWithConfig(pm.ctx, wazero.NewRuntimeConfigInterpreter())
	// instantiate WASI in new runtime for modules that import wasi_snapshot_preview1.
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
		// compile the module from code
		compiled, err := newRt.CompileModule(pm.ctx, wasmBytes)
		if err != nil {
			log.Error().Err(err).Str("file", f.Name()).Msg("failed to compile plugin wasm")

			continue
		}
		// instantiate the compiled module
		module, err := newRt.InstantiateModule(
			pm.ctx,
			compiled,
			wazero.NewModuleConfig().WithName(cmdCode),
		)
		if err != nil {
			log.Error().Err(err).Str("file", f.Name()).Msg("failed to instantiate plugin module")

			continue
		}

		executeFn := module.ExportedFunction("Execute")
		if executeFn == nil {
			log.Warn().Str("file", f.Name()).Msg("plugin does not export Execute function")

			continue
		}

		newPlugins[cmdCode] = &PluginInstance{
			Module:      module,
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

	// returning success

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

	mem := inst.Module.Memory()
	if len(input) > 0 {
		written := mem.Write(0, input)
		if !written {
			return nil, errors.New("failed to write memory")
		}
	}

	results, err := inst.ExecuteFn.Call(pm.ctx, uint64(0), uint64(len(input)))
	if err != nil {
		return nil, fmt.Errorf("plugin execution error: %w", err)
	}

	if len(results) < 2 {
		return nil, errors.New("invalid plugin response")
	}

	outPtr := uint32(results[0])
	outLen := uint32(results[1])
	data, ok := mem.Read(outPtr, outLen)
	if !ok {
		return nil, errors.New("failed to read memory")
	}

	// successful execution

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
