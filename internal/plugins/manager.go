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
	"sync/atomic"
	"time"

	"github.com/andrei-cloud/go_hsm/internal/hsm"
	"github.com/andrei-cloud/go_hsm/pkg/hsmplugin"
	"github.com/rs/zerolog/log"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
)

// PluginMetadata holds cached metadata for a loaded plugin.
type PluginMetadata struct {
	Version     string
	Description string
	Author      string
}

// PluginManager manages WASM plugin instances and supports hot reload.
type PluginManager struct {
	ctx              context.Context //nolint:containedctx // Context is used for plugin lifecycle.
	runtime          wazero.Runtime
	plugins          map[string]PluginInstancePoolInterface
	metadata         map[string]PluginMetadata
	hsm              hsm.HSMInterface
	hostFuncs        HostFunctionsInterface
	bufferPool       *hsmplugin.BufferPool
	executionTimeout time.Duration
	poolSize         int
	inFlight         sync.WaitGroup
	closed           atomic.Bool
	mu               sync.RWMutex
}

// PluginManagerOption defines functional options for PluginManager.
type PluginManagerOption func(*PluginManager)

// WithExecutionTimeout configures the maximum duration for a single plugin execution.
func WithExecutionTimeout(timeout time.Duration) PluginManagerOption {
	return func(pm *PluginManager) {
		if timeout > 0 {
			pm.executionTimeout = timeout
		}
	}
}

// WithPoolSize configures the pool size per plugin.
func WithPoolSize(size int) PluginManagerOption {
	return func(pm *PluginManager) {
		if size > 0 {
			pm.poolSize = size
		}
	}
}

// NewPluginManager returns a PluginManager ready to load plugins.
func NewPluginManager(
	ctx context.Context,
	hsmInstance hsm.HSMInterface,
	opts ...PluginManagerOption,
) *PluginManager {
	pm := &PluginManager{
		ctx:              ctx,
		plugins:          make(map[string]PluginInstancePoolInterface),
		metadata:         make(map[string]PluginMetadata),
		hsm:              hsmInstance,
		bufferPool:       hsmplugin.NewBufferPool(),
		executionTimeout: 2 * time.Second,
		poolSize:         10,
	}

	for _, opt := range opts {
		opt(pm)
	}

	return pm
}

// LoadAll loads all WASM plugins from the specified directory.
// It uses wazero's AOT compilation with a shared compilation cache
// for optimal performance and memory use.
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
		_ = newRt.Close(pm.ctx)
		return fmt.Errorf("failed to register host functions: %w", err)
	}

	newPlugins := make(map[string]PluginInstancePoolInterface)
	newMetadata := make(map[string]PluginMetadata)

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
				_ = instance.Close(pm.ctx)
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

		pool := NewPluginInstancePool(pm.poolSize, factory)

		// Pre-fill pool with one instance and extract metadata
		inst, err := factory()
		if err != nil {
			log.Debug().Err(err).Str("file", f.Name()).Msg("failed to instantiate plugin module")
			_ = pool.Close()
			continue
		}

		// Read and cache plugin metadata
		version, description, author := pm.getPluginMetadataFromInstance(inst)
		newMetadata[cmdCode] = PluginMetadata{
			Version:     version,
			Description: description,
			Author:      author,
		}

		pool.Put(inst)

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
	oldRt := pm.runtime
	oldPlugins := pm.plugins
	pm.runtime = newRt
	pm.plugins = newPlugins
	pm.metadata = newMetadata
	pm.mu.Unlock()

	// Clean up old plugins and runtime asynchronously after grace period if replacing
	if oldRt != nil {
		go func() {
			time.Sleep(100 * time.Millisecond)
			for _, p := range oldPlugins {
				_ = p.Close()
			}
			if err := oldRt.Close(pm.ctx); err != nil {
				log.Error().Err(err).Msg("failed to close previous runtime")
			}
		}()
	}

	return nil
}

// GetPluginMetadata returns the cached metadata for a given plugin command.
func (pm *PluginManager) GetPluginMetadata(cmd string) (string, string, string) {
	pm.mu.RLock()
	meta, ok := pm.metadata[cmd]
	pm.mu.RUnlock()
	if !ok {
		return "N/A", "N/A", "N/A"
	}
	return meta.Version, meta.Description, meta.Author
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

// ExecuteCommand executes a command via its WASM plugin using context.Background.
func (pm *PluginManager) ExecuteCommand(cmd string, input []byte) ([]byte, error) {
	return pm.ExecuteCommandWithContext(context.Background(), cmd, input)
}

// ExecuteCommandWithContext executes a command via its WASM plugin, passing a context for logging
// and adhering to the configured execution timeout and in-flight request tracking.
func (pm *PluginManager) ExecuteCommandWithContext(
	ctx context.Context,
	cmd string,
	input []byte,
) ([]byte, error) {
	if pm.closed.Load() {
		return nil, errors.New("plugin manager is closed")
	}

	pm.inFlight.Add(1)
	defer pm.inFlight.Done()

	pm.mu.RLock()
	pool, ok := pm.plugins[cmd]
	pm.mu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unknown command: %s", cmd)
	}

	execCtx, cancel := context.WithTimeout(ctx, pm.executionTimeout)
	defer cancel()

	inst, err := pool.GetWithContext(execCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to get plugin instance: %w", err)
	}
	defer pool.Put(inst)

	ptr, err := AllocBuffer(execCtx, inst.Module, inst.AllocFn, input)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate memory: %w", err)
	}

	requestID := ""
	if val := ctx.Value("request_id"); val != nil {
		if rid, ok := val.(string); ok {
			requestID = rid
		}
	}
	log.Debug().
		Str("event", "plugin_execution").
		Str("command", cmd).
		Str("request_id", requestID).
		Int("input_size", len(input)).
		Hex("input", input).
		Msg("executing plugin")

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

// Close gracefully stops accepting new requests, waits for in-flight executions, and releases all resources.
func (pm *PluginManager) Close() error {
	if !pm.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Wait for in-flight requests to complete (with a short timeout)
	done := make(chan struct{})
	go func() {
		pm.inFlight.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		log.Warn().Msg("timed out waiting for in-flight plugin executions on close")
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	for _, pool := range pm.plugins {
		if pool != nil {
			_ = pool.Close()
		}
	}
	pm.plugins = nil
	pm.metadata = nil

	if pm.runtime != nil {
		log.Debug().Msg("closing wazero runtime and freeing WASM memory")
		if err := pm.runtime.Close(pm.ctx); err != nil {
			return fmt.Errorf("error closing runtime: %w", err)
		}
		pm.runtime = nil
	}

	// Clean up buffer pool
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
func (pm *PluginManager) HSM() hsm.HSMInterface {
	return pm.hsm
}

// CleanupPooledBuffers releases the current buffer pool and creates a new one.
func (pm *PluginManager) CleanupPooledBuffers() {
	pm.bufferPool = hsmplugin.NewBufferPool()
	pm.bufferPool.Prewarm(10)
	log.Debug().Msg("buffer pool recreated and prewarmed")
}
