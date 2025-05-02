package plugins

import (
	"context"
	"encoding/hex"
	"errors"
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

// PluginManager manages WASM plugin instances and supports hot reload by recreating the runtime.
type PluginManager struct {
	//nolint:containedctx // Context is stored in the struct intentionally to allow reuse across plugin operations.
	ctx     context.Context
	runtime wazero.Runtime
	plugins map[string]*PluginInstance
	hsm     *hsm.HSM
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
func NewPluginManager(ctx context.Context, hsmInstance *hsm.HSM) *PluginManager {
	return &PluginManager{ctx: ctx, plugins: make(map[string]*PluginInstance), hsm: hsmInstance}
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

	// Create env module with LMK host functions
	envBuilder := newRt.NewHostModuleBuilder("env")

	// Add log debug function
	envBuilder.NewFunctionBuilder().
		WithFunc(func(_ context.Context, m api.Module, ptr, length uint32) {
			data, ok := m.Memory().Read(ptr, length)
			if !ok {
				log.Error().Msg("failed to read memory in log_debug")
				return
			}
			log.Debug().
				Str("event", "plugin_debug").
				Str("debug_msg", string(data)).
				Msg("plugin debug message")
		}).
		Export("log_debug").
		// Add LMK encryption/decryption functions
		NewFunctionBuilder().
		WithFunc(func(_ context.Context, m api.Module, ptr, length uint32) uint64 {
			data, ok := m.Memory().Read(ptr, length)
			if !ok {
				log.Error().Msg("failed to read memory in DecryptUnderLMK")
				return 0
			}
			log.Debug().
				Str("event", "decrypt_lmk").
				Str("input_hex", hex.EncodeToString(data)).
				Msg("calling DecryptUnderLMK")
			decrypted, err := pm.hsm.DecryptUnderLMK(data)
			if err != nil {
				log.Error().Err(err).Msg("DecryptUnderLMK failed")
				return 0
			}

			return hsmplugin.PackResult(hsmplugin.WriteBytes(decrypted))
		}).
		Export("DecryptUnderLMK").
		NewFunctionBuilder().
		WithFunc(func(_ context.Context, m api.Module, ptr, length uint32) uint64 {
			data, ok := m.Memory().Read(ptr, length)
			if !ok {
				log.Error().Msg("failed to read memory in EncryptUnderLMK")
				return 0
			}
			log.Debug().
				Str("event", "encrypt_lmk").
				Str("input_hex", hex.EncodeToString(data)).
				Msg("calling EncryptUnderLMK")
			encrypted, err := pm.hsm.EncryptUnderLMK(data)
			if err != nil {
				log.Error().Err(err).Msg("EncryptUnderLMK failed")
				return 0
			}
			log.Debug().
				Str("event", "encrypt_lmk_result").
				Str("output_hex", hex.EncodeToString(encrypted)).
				Msg("EncryptUnderLMK result")

			return hsmplugin.PackResult(hsmplugin.WriteBytes(encrypted))
		}).
		Export("EncryptUnderLMK")

	// Instantiate the env module
	if _, err := envBuilder.Instantiate(pm.ctx); err != nil {
		return fmt.Errorf("failed to instantiate env module: %w", err)
	}

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

	ptr, inputLen := hsmplugin.WriteBytes(input)
	if inputLen == 0 {
		return nil, errors.New("failed to write input to memory")
	}

	if !inst.Module.Memory().Write(ptr, input[:inputLen]) {
		return nil, errors.New("failed to write input to memory")
	}

	// execute plugin and get combined result.
	combined, err := CallExecute(pm.ctx, inst.ExecuteFn, ptr, inputLen)
	if err != nil {
		return nil, fmt.Errorf("plugin execution error: %w", err)
	}

	// unpack result into pointer and length.
	outPtr, outLen := hsmplugin.UnpackResult(combined)

	// read response from guest memory.
	resp, err := ReadResult(inst.Module, outPtr, outLen)
	if err != nil {
		return nil, fmt.Errorf("%w", err)
	}

	log.Debug().
		Str("event", "plugin_response").
		Str("command", cmd).
		Str("response_hex", hex.EncodeToString(resp)).
		Msg("plugin execution response")

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

// HSM returns the HSM instance used by this plugin manager.
func (pm *PluginManager) HSM() *hsm.HSM {
	return pm.hsm
}

// Close closes the underlying WASM runtime.
func (pm *PluginManager) Close() error {
	return pm.runtime.Close(pm.ctx)
}
