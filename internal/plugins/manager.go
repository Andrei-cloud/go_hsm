// Package plugins manages the loading and execution of WASM plugin instances for HSM commands.
package plugins

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/andrei-cloud/go_hsm/internal/hsm"
	"github.com/andrei-cloud/go_hsm/pkg/hsmplugin"
	"github.com/rs/zerolog/log"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// PluginManager manages WASM plugin instances and supports hot reload.
type PluginManager struct {
	ctx        context.Context
	runtime    wazero.Runtime
	plugins    map[string]*PluginInstance
	hsm        *hsm.HSM
	hostFuncs  *HostFunctions
	bufferPool *hsmplugin.BufferPool
	mu         sync.RWMutex
}

// PluginInstance holds a WASM module instance.
type PluginInstance struct {
	Module        api.Module
	AllocFn       api.Function
	ExecuteFn     api.Function
	VersionFn     api.Function
	DescriptionFn api.Function
	AuthorFn      api.Function
	mu            sync.Mutex
}

// NewPluginManager returns a PluginManager ready to load plugins.
func NewPluginManager(
	ctx context.Context,
	hsmInstance *hsm.HSM,
) *PluginManager {
	pm := &PluginManager{
		ctx:        ctx,
		plugins:    make(map[string]*PluginInstance),
		hsm:        hsmInstance,
		bufferPool: hsmplugin.NewBufferPool(),
	}

	return pm
}

// LoadAll loads all WASM plugins from the specified directory.
// It uses wazero's AOT compilation with a shared compilation cache
// for optimal performance and memory use. This approach ensures
// high-throughput plugin execution while controlling memory growth.
func (pm *PluginManager) LoadAll(dir string) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read plugin directory: %w", err)
	}

	// Create new runtime with compilation cache for better performance
	runtimeConfig := wazero.NewRuntimeConfig().
		WithCompilationCache(wazero.NewCompilationCache())
	newRt := wazero.NewRuntimeWithConfig(pm.ctx, runtimeConfig)

	// Initialize WASI
	wasi_snapshot_preview1.MustInstantiate(pm.ctx, newRt)

	// Create and register host functions
	pm.hostFuncs = NewHostFunctions(newRt, pm.hsm)
	if err := pm.hostFuncs.Register(pm.ctx); err != nil {
		return fmt.Errorf("failed to register host functions: %w", err)
	}

	newPlugins := make(map[string]*PluginInstance)

	for _, f := range files {
		if f.IsDir() || filepath.Ext(f.Name()) != ".wasm" {
			continue
		}

		cmdCode := strings.TrimSuffix(f.Name(), ".wasm")

		// Load and compile WASM module
		wasmBytes, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			log.Debug().
				Err(err).
				Str("file", f.Name()).
				Msg("failed to read plugin file")

			continue
		}

		compiled, err := newRt.CompileModule(pm.ctx, wasmBytes)
		if err != nil {
			log.Debug().
				Err(err).
				Str("file", f.Name()).
				Msg("failed to compile plugin module")

			continue
		}

		// Create module config
		cfg := wazero.NewModuleConfig().
			WithName(cmdCode).
			WithStartFunctions()

		// Instantiate module
		instance, err := newRt.InstantiateModule(pm.ctx, compiled, cfg)
		if err != nil {
			log.Debug().
				Err(err).
				Str("file", f.Name()).
				Msg("failed to instantiate plugin module")

			continue
		}

		// Get required functions
		allocFn := instance.ExportedFunction("Alloc")
		executeFn := instance.ExportedFunction("Execute")
		versionFn := instance.ExportedFunction("version")
		descriptionFn := instance.ExportedFunction("description")
		authorFn := instance.ExportedFunction("author")
		if allocFn == nil || executeFn == nil || versionFn == nil ||
			descriptionFn == nil || authorFn == nil {
			log.Debug().
				Str("file", f.Name()).
				Msg("plugin missing required exports")

			continue
		}

		// Create plugin instance
		newPlugins[cmdCode] = &PluginInstance{
			Module:        instance,
			AllocFn:       allocFn,
			ExecuteFn:     executeFn,
			VersionFn:     versionFn,
			DescriptionFn: descriptionFn,
			AuthorFn:      authorFn,
		}
	}

	// Update runtime and plugins atomically
	pm.mu.Lock()
	if pm.runtime != nil {
		if err := pm.runtime.Close(pm.ctx); err != nil {
			log.Error().
				Err(err).
				Msg("failed to close previous runtime")
		}
	}
	pm.runtime = newRt
	pm.plugins = newPlugins
	pm.mu.Unlock()

	return nil
}

// ExecuteCommand executes a command via its WASM plugin.
func (pm *PluginManager) ExecuteCommand(cmd string, input []byte) ([]byte, error) {
	pm.mu.RLock()
	inst, ok := pm.plugins[cmd]
	pm.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown command: %s", cmd)
	}

	inst.mu.Lock()
	defer inst.mu.Unlock()

	// Allocate guest memory for input
	ptr, err := AllocBuffer(pm.ctx, inst.Module, inst.AllocFn, input)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate memory: %w", err)
	}

	log.Debug().
		Str("event", "plugin_execution").
		Str("command", cmd).
		Int("input_size", len(input)).
		Hex("input", input).
		Msg("executing plugin")

	// Execute plugin
	res, err := CallExecute(pm.ctx, inst.ExecuteFn, ptr, uint32(len(input)))
	if err != nil {
		return nil, fmt.Errorf("plugin execution failed: %w", err)
	}

	// Read result from plugin memory
	result, err := ReadBuffer(inst.Module, hsmplugin.Buffer(res))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	log.Debug().
		Str("event", "plugin_response").
		Str("command", cmd).
		Int("output_size", len(result)).
		Hex("output", result).
		Msg("plugin execution complete")

	return result, nil
}

// Close releases all resources.
func (pm *PluginManager) Close() error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if pm.runtime != nil {
		log.Debug().Msg("closing wazero runtime and freeing WASM memory")
		// This properly frees WASM linear memory
		if err := pm.runtime.Close(pm.ctx); err != nil {
			return fmt.Errorf("error closing runtime: %w", err)
		}
		pm.runtime = nil
	}

	// Clean up buffer pool to release any large cached slices
	pm.CleanupPooledBuffers()

	return nil
}

// ListPlugins returns all loaded plugin names.
func (pm *PluginManager) ListPlugins() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	result := make([]string, 0, len(pm.plugins))
	for cmd := range pm.plugins {
		result = append(result, cmd)
	}

	return result
}

// HSM returns the HSM instance.
func (pm *PluginManager) HSM() *hsm.HSM {
	return pm.hsm
}

// CleanupPooledBuffers releases the current buffer pool and creates a new one.
// This is useful for releasing large cached slices back to Go's allocator
// during idle periods or after processing large payloads.
func (pm *PluginManager) CleanupPooledBuffers() {
	oldPool := pm.bufferPool

	// Create new pool first to avoid any race conditions
	pm.bufferPool = hsmplugin.NewBufferPool()

	// Pre-warm the pool with a few buffers for common sizes to avoid cold starts
	pm.bufferPool.Prewarm(10)

	log.Debug().
		Interface("stats", oldPool.Stats()).
		Msg("buffer pool statistics before cleanup")
}
