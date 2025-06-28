package plugins

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/hsm"
	"github.com/rs/zerolog/log"
	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// HostFunctions provides WASM host functions for plugins to use.
type HostFunctions struct {
	runtime wazero.Runtime
	builder wazero.HostModuleBuilder
	hsm     *hsm.HSM
}

// NewHostFunctions creates a new host functions provider.
func NewHostFunctions(runtime wazero.Runtime, hsmInstance *hsm.HSM) *HostFunctions {
	return &HostFunctions{
		runtime: runtime,
		builder: runtime.NewHostModuleBuilder("env"),
		hsm:     hsmInstance,
	}
}

// Register adds all host functions to the WASM runtime.
func (h *HostFunctions) Register(ctx context.Context) error {
	// Logging functions
	h.builder.NewFunctionBuilder().
		WithFunc(h.logDebug).
		Export("log_debug")

	h.builder.NewFunctionBuilder().
		WithFunc(h.logInfo).
		Export("log_info")

	h.builder.NewFunctionBuilder().
		WithFunc(h.logError).
		Export("log_error")

	// JSON handling
	h.builder.NewFunctionBuilder().
		WithFunc(h.jsonParse).
		Export("json_parse")

	h.builder.NewFunctionBuilder().
		WithFunc(h.jsonStringify).
		Export("json_stringify")

	// HSM cryptographic operations
	h.builder.NewFunctionBuilder().
		WithFunc(h.encryptUnderLMK).
		Export("EncryptUnderLMK")

	h.builder.NewFunctionBuilder().
		WithFunc(h.decryptUnderLMK).
		Export("DecryptUnderLMK")

	h.builder.NewFunctionBuilder().
		WithFunc(h.generateRandomKey).
		Export("RandomKey")

	// Instantiate the module
	_, err := h.builder.Instantiate(ctx)
	if err != nil {
		return fmt.Errorf("failed to instantiate host functions module: %w", err)
	}

	return nil
}

// readMemory safely reads bytes from WASM module memory.
func readMemory(mod api.Module, ptr, size uint32) ([]byte, error) {
	if mod == nil {
		return nil, errors.New("nil module")
	}

	memory := mod.Memory()
	if memory == nil {
		return nil, errors.New("no memory exported")
	}

	data, ok := memory.Read(ptr, size)
	if !ok {
		return nil, fmt.Errorf("failed to read memory at %d[%d]", ptr, size)
	}

	return data, nil
}

// writeMemory safely writes bytes to WASM module memory.
func writeMemory(mod api.Module, ptr uint32, data []byte) error {
	if mod == nil {
		return errors.New("nil module")
	}

	memory := mod.Memory()
	if memory == nil {
		return errors.New("no memory exported")
	}

	if !memory.Write(ptr, data) {
		return fmt.Errorf("failed to write memory at %d[%d]", ptr, len(data))
	}

	return nil
}

func (h *HostFunctions) logDebug(ctx context.Context, mod api.Module, ptr, size uint32) {
	data, err := readMemory(mod, ptr, size)
	if err != nil {
		log.Error().Err(err).Msg("failed to read debug log message")

		return
	}
	requestID := ""
	if val := ctx.Value("request_id"); val != nil {
		if rid, ok := val.(string); ok {
			requestID = rid
		}
	}
	log.Debug().
		Str("source", "wasm").
		Str("request_id", requestID).
		Msg(string(data))
}

func (h *HostFunctions) logInfo(ctx context.Context, mod api.Module, ptr, size uint32) {
	data, err := readMemory(mod, ptr, size)
	if err != nil {
		log.Error().Err(err).Msg("failed to read info log message")

		return
	}
	requestID := ""
	if val := ctx.Value("request_id"); val != nil {
		if rid, ok := val.(string); ok {
			requestID = rid
		}
	}
	log.Info().
		Str("source", "wasm").
		Str("request_id", requestID).
		Msg(string(data))
}

func (h *HostFunctions) logError(ctx context.Context, mod api.Module, ptr, size uint32) {
	data, err := readMemory(mod, ptr, size)
	if err != nil {
		log.Error().Err(err).Msg("failed to read error log message")

		return
	}
	requestID := ""
	if val := ctx.Value("request_id"); val != nil {
		if rid, ok := val.(string); ok {
			requestID = rid
		}
	}
	log.Error().
		Str("source", "wasm").
		Str("request_id", requestID).
		Msg(string(data))
}

func (h *HostFunctions) jsonParse(
	_ context.Context,
	mod api.Module,
	jsonPtr, jsonLen uint32,
) uint64 {
	jsonData, err := readMemory(mod, jsonPtr, jsonLen)
	if err != nil {
		log.Error().Err(err).Msg("failed to read JSON data")
		return 0
	}

	var parsed any
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		log.Error().Err(err).Msg("failed to parse JSON")
		return 0
	}

	// Store parsed data in module memory for future reference
	// This is just a basic example - you'd need to implement a proper
	// mechanism to store and reference parsed JSON data
	return 1
}

func (h *HostFunctions) jsonStringify(_ context.Context, mod api.Module, ptr, size uint32) uint64 {
	data, err := readMemory(mod, ptr, size)
	if err != nil {
		log.Error().Err(err).Msg("failed to read data for JSON stringify")
		return 0
	}

	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		log.Error().Err(err).Msg("failed to parse data for JSON stringify")
		return 0
	}

	jsonData, err := json.Marshal(value)
	if err != nil {
		log.Error().Err(err).Msg("failed to stringify JSON")
		return 0
	}

	allocFn := mod.ExportedFunction("Alloc")
	results, err := allocFn.Call(context.Background(), uint64(len(jsonData)))
	if err != nil || len(results) == 0 {
		log.Error().Err(err).Msg("failed to allocate memory for JSON string")
		return 0
	}

	resultPtr := uint32(results[0])
	if err := writeMemory(mod, resultPtr, jsonData); err != nil {
		log.Error().Err(err).Msg("failed to write JSON string to memory")
		return 0
	}

	return uint64(resultPtr)<<32 | uint64(len(jsonData))
}

func (h *HostFunctions) hsmCryptoOperation(
	ctx context.Context,
	mod api.Module,
	dataPtr, dataLen, typePtr, typeLen, schemeTagRaw uint32,
	isEncrypt bool,
) uint64 {
	data, err := readMemory(mod, dataPtr, dataLen)
	if err != nil {
		log.Error().Err(err).Msg("failed to read data for crypto operation")
		return 0
	}

	keyType, err := readMemory(mod, typePtr, typeLen)
	if err != nil {
		log.Error().Err(err).Msg("failed to read key type")
		return 0
	}

	schemeTag := byte(schemeTagRaw)

	var result []byte
	if isEncrypt {
		result, err = h.hsm.EncryptKeyWithVariantScheme(data, string(keyType), schemeTag)
	} else {
		result, err = h.hsm.DecryptKeyWithVariantScheme(data, string(keyType), schemeTag)
	}

	if err != nil {
		log.Error().Err(err).Msg("failed to perform crypto operation")
		return 0
	}

	allocFn := mod.ExportedFunction("Alloc")
	results, err := allocFn.Call(ctx, uint64(len(result)))
	if err != nil || len(results) == 0 {
		log.Error().Err(err).Msg("failed to allocate memory for crypto result")
		return 0
	}

	resultPtr := uint32(results[0])
	if err := writeMemory(mod, resultPtr, result); err != nil {
		log.Error().Err(err).Msg("failed to write crypto result to memory")
		return 0
	}

	return uint64(resultPtr)<<32 | uint64(len(result))
}

func (h *HostFunctions) encryptUnderLMK(
	ctx context.Context,
	mod api.Module,
	dataPtr, dataLen, typePtr, typeLen, schemeTagRaw uint32,
) uint64 {
	return h.hsmCryptoOperation(ctx, mod, dataPtr, dataLen, typePtr, typeLen, schemeTagRaw, true)
}

func (h *HostFunctions) decryptUnderLMK(
	ctx context.Context,
	mod api.Module,
	dataPtr, dataLen, typePtr, typeLen, schemeTagRaw uint32,
) uint64 {
	return h.hsmCryptoOperation(ctx, mod, dataPtr, dataLen, typePtr, typeLen, schemeTagRaw, false)
}

func (h *HostFunctions) generateRandomKey(_ context.Context, mod api.Module, length uint32) uint64 {
	key, err := h.hsm.GenerateRandomKey(int(length))
	if err != nil {
		log.Error().Err(err).Msg("failed to generate random key")
		return 0
	}

	allocFn := mod.ExportedFunction("Alloc")
	results, err := allocFn.Call(context.Background(), uint64(len(key)))
	if err != nil || len(results) == 0 {
		log.Error().Err(err).Msg("failed to allocate memory for random key")
		return 0
	}

	resultPtr := uint32(results[0])
	if err := writeMemory(mod, resultPtr, key); err != nil {
		log.Error().Err(err).Msg("failed to write random key to memory")
		return 0
	}

	return uint64(resultPtr)<<32 | uint64(len(key))
}