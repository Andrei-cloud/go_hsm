// Package plugins manages the loading and execution of WASM plugin instances for HSM commands.
package plugins

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/andrei-cloud/go_hsm/internal/hsm"
	"github.com/andrei-cloud/go_hsm/pkg/hsmplugin"
	"github.com/rs/zerolog/log"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// PluginManager manages WASM plugin instances and supports hot reload.
type PluginManager struct {
	ctx        context.Context //nolint:containedctx // Context is used for plugin lifecycle.
	runtime    wazero.Runtime
	plugins    map[string]*PluginInstancePool
	hsm        *hsm.HSM
	hostFuncs  *HostFunctions
	bufferPool *hsmplugin.BufferPool
	mu         sync.RWMutex
}

// NewPluginManager returns a PluginManager ready to load plugins.
func NewPluginManager(
	ctx context.Context,
	hsmInstance *hsm.HSM,
) *PluginManager {
	pm := &PluginManager{
		ctx:        ctx,
		plugins:    make(map[string]*PluginInstancePool),
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

	newPlugins := make(map[string]*PluginInstancePool)

	for _, f := range files {
		if f.IsDir() || filepath.Ext(f.Name()) != ".wasm" {
			continue
		}
		cmdCode := strings.TrimSuffix(f.Name(), ".wasm")
		wasmBytes, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			log.Debug().Err(err).Str("file", f.Name()).Msg("failed to read plugin file")
			continue
		}
		compiled, err := newRt.CompileModule(pm.ctx, wasmBytes)
		if err != nil {
			log.Debug().Err(err).Str("file", f.Name()).Msg("failed to compile plugin module")
			continue
		}
		cfg := wazero.NewModuleConfig().WithName(cmdCode).WithStartFunctions()
		factory := func() (*PluginInstance, error) {
			instance, err := newRt.InstantiateModule(pm.ctx, compiled, cfg)
			if err != nil {
				return nil, err
			}
			allocFn := instance.ExportedFunction("Alloc")
			executeFn := instance.ExportedFunction("Execute")
			versionFn := instance.ExportedFunction("version")
			descriptionFn := instance.ExportedFunction("description")
			authorFn := instance.ExportedFunction("author")
			if allocFn == nil || executeFn == nil || versionFn == nil || descriptionFn == nil ||
				authorFn == nil {
				return nil, errors.New("plugin missing required exports")
			}

			return &PluginInstance{
				Module:        instance,
				AllocFn:       allocFn,
				ExecuteFn:     executeFn,
				VersionFn:     versionFn,
				DescriptionFn: descriptionFn,
				AuthorFn:      authorFn,
			}, nil
		}
		pool := &PluginInstancePool{
			pool:    make(chan *PluginInstance, 10),
			maxSize: 10,
			factory: factory,
		}
		// Pre-fill pool with one instance
		inst, err := factory()
		if err != nil {
			log.Debug().Err(err).Str("file", f.Name()).Msg("failed to instantiate plugin module")
			continue
		}
		pool.pool <- inst
		// Validate plugin metadata
		version, description, author := pm.getPluginMetadataFromInstance(inst)
		if version == "N/A" || description == "N/A" || author == "N/A" {
			log.Warn().
				Str("file", f.Name()).
				Str("version", version).
				Str("description", description).
				Str("author", author).
				Msg("plugin metadata missing or malformed")
		}
		newPlugins[cmdCode] = pool
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

// GetPluginMetadata returns the metadata for a given plugin command.
func (pm *PluginManager) GetPluginMetadata(cmd string) (string, string, string) {
	pm.mu.RLock()
	pool, ok := pm.plugins[cmd]
	pm.mu.RUnlock()
	if !ok {
		return "N/A", "N/A", "N/A"
	}
	inst, err := pool.Get()
	if err != nil {
		return "N/A", "N/A", "N/A"
	}
	defer pool.Put(inst)
	version, description, author := pm.getPluginMetadataFromInstance(inst)

	return version, description, author
}

// getPluginMetadataFromInstance is a helper for metadata validation at load time.
func (pm *PluginManager) getPluginMetadataFromInstance(
	inst *PluginInstance,
) (string, string, string) {
	var version, description, author string
	ctx := pm.ctx
	if inst.VersionFn != nil {
		if results, err := inst.VersionFn.Call(ctx); err == nil && len(results) > 0 {
			ptr, size := hsmplugin.UnpackResult(results[0])
			if size > 0 {
				if bytes, ok := inst.Module.Memory().Read(ptr, size); ok {
					version = string(bytes)
				}
			}
		}
	}
	if inst.DescriptionFn != nil {
		if results, err := inst.DescriptionFn.Call(ctx); err == nil && len(results) > 0 {
			ptr, size := hsmplugin.UnpackResult(results[0])
			if size > 0 {
				if bytes, ok := inst.Module.Memory().Read(ptr, size); ok {
					description = string(bytes)
				}
			}
		}
	}
	if inst.AuthorFn != nil {
		if results, err := inst.AuthorFn.Call(ctx); err == nil && len(results) > 0 {
			ptr, size := hsmplugin.UnpackResult(results[0])
			if size > 0 {
				if bytes, ok := inst.Module.Memory().Read(ptr, size); ok {
					author = string(bytes)
				}
			}
		}
	}
	if version == "" {
		version = "N/A"
	}
	if description == "" {
		description = "N/A"
	}
	if author == "" {
		author = "N/A"
	}

	return version, description, author
}

// ExecuteCommand executes a command via its WASM plugin.
func (pm *PluginManager) ExecuteCommand(cmd string, input []byte) ([]byte, error) {
	pm.mu.RLock()
	pool, ok := pm.plugins[cmd]
	pm.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown command: %s", cmd)
	}
	inst, err := pool.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to get plugin instance: %w", err)
	}
	defer pool.Put(inst)

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

	// Add context timeout to avoid hung plugins
	ctx, cancel := context.WithTimeout(pm.ctx, 2*time.Second) // TODO: make timeout configurable
	defer cancel()

	// TODO: Update CallExecute and plugin ABI to use WASM multi-value returns for pointer/length
	res, err := CallExecute(ctx, inst.ExecuteFn, ptr, uint32(len(input)))
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

// ExecuteCommandWithContext executes a command via its WASM plugin, passing a context for logging.
func (pm *PluginManager) ExecuteCommandWithContext(
	ctx context.Context,
	cmd string,
	input []byte,
) ([]byte, error) {
	pm.mu.RLock()
	pool, ok := pm.plugins[cmd]
	pm.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown command: %s", cmd)
	}
	inst, err := pool.Get()
	if err != nil {
		return nil, fmt.Errorf("failed to get plugin instance: %w", err)
	}
	defer pool.Put(inst)

	ptr, err := AllocBuffer(pm.ctx, inst.Module, inst.AllocFn, input)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate memory: %w", err)
	}

	requestID, _ := ctx.Value("request_id").(string)
	log.Debug().
		Str("event", "plugin_execution").
		Str("command", cmd).
		Str("request_id", requestID).
		Int("input_size", len(input)).
		Hex("input", input).
		Msg("executing plugin")

	execCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()

	res, err := CallExecute(execCtx, inst.ExecuteFn, ptr, uint32(len(input)))
	if err != nil {
		return nil, fmt.Errorf("plugin execution failed: %w", err)
	}

	result, err := ReadBuffer(inst.Module, hsmplugin.Buffer(res))
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	log.Debug().
		Str("event", "plugin_response").
		Str("command", cmd).
		Str("request_id", requestID).
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
