// Package plugins manages the loading and execution of WASM plugin instances for HSM commands.
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
	"github.com/andrei-cloud/go_hsm/internal/logging"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
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

// PluginInstance holds a WASM module and its execute and allocation functions.
type PluginInstance struct {
	Module      api.Module
	AllocFn     api.Function
	ExecuteFn   api.Function
	Description string
	mu          sync.Mutex
}

// NewPluginManager returns a PluginManager ready to load plugins using the provided context and HSM instance.
func NewPluginManager(ctx context.Context, hsmInstance *hsm.HSM) *PluginManager {
	return &PluginManager{ctx: ctx, plugins: make(map[string]*PluginInstance), hsm: hsmInstance}
}

// LoadAll loads all WASM plugins from the specified directory, instantiating each and storing it by command code.
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
				Str("msg", logging.FormatData(data)).
				Msg("wasm")
		}).
		Export("log_debug").
		// DecryptUnderVariantLMK decrypts a key using the Variant LMK scheme.
		// Parameters:
		// - encryptedKeyPtr: uint32, pointer to the encrypted key data in guest memory.
		// - encryptedKeyLen: uint32, length of the encrypted key data.
		// - keyTypeStrPtr: uint32, pointer to the key type string (e.g., "001", "209") in guest memory.
		// - keyTypeStrLen: uint32, length of the key type string.
		// - schemeTag: uint32, the scheme tag ('U' or 'T'). Note: passed as uint32 from WASM, converted to byte.
		// Returns: uint64, packed pointer and length of the decrypted key in guest memory, or 0 on error.
		NewFunctionBuilder().
		WithFunc(func(_ context.Context, m api.Module,
			encryptedKeyPtr, encryptedKeyLen,
			keyTypeStrPtr, keyTypeStrLen, schemeTagRaw uint32,
		) uint64 {
			encryptedKeyData, ok := m.Memory().Read(encryptedKeyPtr, encryptedKeyLen)
			if !ok {
				log.Error().
					Msg("failed to read encryptedKeyData from guest memory in DecryptUnderVariantLMK")
				return 0
			}
			keyTypeStrBytes, ok := m.Memory().Read(keyTypeStrPtr, keyTypeStrLen)
			if !ok {
				log.Error().
					Msg("failed to read keyTypeStrBytes from guest memory in DecryptUnderVariantLMK")
				return 0
			}
			keyTypeStr := string(keyTypeStrBytes)
			schemeTag := byte(schemeTagRaw) // schemeTag is a single character like 'U' or 'T'

			log.Debug().
				Str("event", "decrypt_variant_lmk").
				Str("encrypted_key_hex", hex.EncodeToString(encryptedKeyData)).
				Str("key_type", keyTypeStr).
				Str("scheme_tag", string(schemeTag)).
				Msg("calling DecryptKeyWithVariantScheme")

			decrypted, err := pm.hsm.DecryptKeyWithVariantScheme(
				encryptedKeyData,
				keyTypeStr,
				schemeTag,
			)
			if err != nil {
				log.Error().Err(err).Msg("DecryptKeyWithVariantScheme failed")
				return 0
			}

			// allocate guest memory for decrypted data
			allocFn := m.ExportedFunction("Alloc")
			results, err := allocFn.Call(context.Background(), uint64(len(decrypted)))
			if err != nil || len(results) == 0 {
				log.Error().
					Err(err).
					Msg("failed to alloc guest memory for DecryptKeyWithVariantScheme result")

				return 0
			}
			packed := results[0]
			dstPtr := api.DecodeU32(packed >> 32)
			if !m.Memory().Write(dstPtr, decrypted) {
				log.Error().
					Msg("failed to write decrypted data to guest memory for DecryptKeyWithVariantScheme")
				return 0
			}

			return packed
		}).
		Export("DecryptUnderLMK").
		// Keeping original export name for now, consider renaming to DecryptUnderVariantLMK if feasible for plugins
		// EncryptUnderVariantLMK encrypts a key using the Variant LMK scheme.
		// Parameters:
		// - plainKeyPtr: uint32, pointer to the plaintext key data in guest memory.
		// - plainKeyLen: uint32, length of the plaintext key data.
		// - keyTypeStrPtr: uint32, pointer to the key type string (e.g., "001", "209") in guest memory.
		// - keyTypeStrLen: uint32, length of the key type string.
		// - schemeTag: uint32, the scheme tag ('U' or 'T'). Note: passed as uint32 from WASM, converted to byte.
		// Returns: uint64, packed pointer and length of the encrypted key in guest memory, or 0 on error.
		NewFunctionBuilder().
		WithFunc(func(_ context.Context, m api.Module,
			plainKeyPtr, plainKeyLen,
			keyTypeStrPtr, keyTypeStrLen, schemeTagRaw uint32,
		) uint64 {
			plainKeyData, ok := m.Memory().Read(plainKeyPtr, plainKeyLen)
			if !ok {
				log.Error().
					Msg("failed to read plainKeyData from guest memory in EncryptUnderVariantLMK")

				return 0
			}
			keyTypeStrBytes, ok := m.Memory().Read(keyTypeStrPtr, keyTypeStrLen)
			if !ok {
				log.Error().
					Msg("failed to read keyTypeStrBytes from guest memory in EncryptUnderVariantLMK")

				return 0
			}
			keyTypeStr := string(keyTypeStrBytes)
			schemeTag := byte(schemeTagRaw) // schemeTag is a single character like 'U' or 'T'

			log.Debug().
				Str("event", "encrypt_variant_lmk").
				Str("plain_key_hex", hex.EncodeToString(plainKeyData)).
				Str("key_type", keyTypeStr).
				Str("scheme_tag", string(schemeTag)).
				Msg("calling EncryptKeyWithVariantScheme")

			encrypted, err := pm.hsm.EncryptKeyWithVariantScheme(
				plainKeyData,
				keyTypeStr,
				schemeTag,
			)
			if err != nil {
				log.Error().Err(err).Msg("EncryptKeyWithVariantScheme failed")
				return 0
			}
			log.Debug().
				Str("event", "encrypt_variant_lmk_result").
				Str("output_hex", hex.EncodeToString(encrypted)).
				Msg("EncryptKeyWithVariantScheme result")

			// allocate guest memory for encrypted data
			allocFn := m.ExportedFunction("Alloc")
			results, err := allocFn.Call(context.Background(), uint64(len(encrypted)))
			if err != nil || len(results) == 0 {
				log.Error().
					Err(err).
					Msg("failed to alloc guest memory for EncryptKeyWithVariantScheme result")

				return 0
			}
			packed := results[0]
			dstPtr := api.DecodeU32(packed >> 32)
			if !m.Memory().Write(dstPtr, encrypted) {
				log.Error().
					Msg("failed to write encrypted data to guest memory for EncryptKeyWithVariantScheme")

				return 0
			}

			return packed
		}).
		Export("EncryptUnderLMK").
		// RandomKey function to generate a random key. receives length of the key and returns the key.
		NewFunctionBuilder().
		WithFunc(func(_ context.Context, m api.Module, length uint32) uint64 {
			log.Debug().
				Str("event", "random_key").
				Uint32("length", length).
				Msg("calling RandomKey")

			key, err := cryptoutils.GenerateRandomKey(int(length))
			if err != nil {
				log.Error().Err(err).Msg("RandomKey failed")

				return 0
			}
			log.Debug().
				Str("event", "random_key_result").
				Str("output_hex", hex.EncodeToString(key)).
				Msg("RandomKey result")
			// allocate guest memory for random key
			allocFn := m.ExportedFunction("Alloc")
			results, err := allocFn.Call(context.Background(), uint64(len(key)))
			if err != nil || len(results) == 0 {
				log.Error().Err(err).Msg("failed to alloc guest memory for RandomKey")
				return 0
			}
			packed := results[0]
			dst := api.DecodeU32(packed >> 32)
			if !m.Memory().Write(dst, key) {
				log.Error().Msg("failed to write random key to guest memory")

				return 0
			}

			return packed
		}).
		Export("RandomKey")

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

		allocFn := module.ExportedFunction("Alloc")
		if allocFn == nil {
			log.Warn().Str("file", f.Name()).Msg("plugin does not export Alloc function")

			continue
		}

		newPlugins[cmdCode] = &PluginInstance{
			Module:      module,
			ExecuteFn:   executeFn,
			AllocFn:     allocFn,
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

// ExecuteCommand executes the given command with input via the corresponding WASM plugin and returns the response bytes.
func (pm *PluginManager) ExecuteCommand(cmd string, input []byte) ([]byte, error) {
	pm.mu.RLock()
	inst, ok := pm.plugins[cmd]
	pm.mu.RUnlock()
	if !ok {
		return nil, errors.New("unknown command")
	}
	inst.mu.Lock()
	defer inst.mu.Unlock()

	// allocate guest memory for input and copy it in
	ptr, err := AllocBuffer(pm.ctx, inst.Module, inst.AllocFn, input)
	if err != nil {
		return nil, fmt.Errorf("failed to allocate memory: %w", err)
	}

	log.Debug().
		Str("event", "plugin_execution").
		Str("command", cmd).
		Str("request_hex", hex.EncodeToString(input)).
		Msg("plugin execution call")

	// execute plugin and get combined result.
	res, err := CallExecute(pm.ctx, inst.ExecuteFn, ptr, uint32(len(input)))
	if err != nil {
		return nil, fmt.Errorf("plugin execution error: %w", err)
	}

	// read response from guest memory.
	resp, err := ReadBuffer(inst.Module, hsmplugin.Buffer(res))
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

// GetDescription returns the description of the given command or the command code if not found.
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

// Close closes the underlying WASM runtime and releases resources.
func (pm *PluginManager) Close() error {
	return pm.runtime.Close(pm.ctx)
}
