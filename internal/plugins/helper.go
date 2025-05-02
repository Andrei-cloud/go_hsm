package plugins

import (
	"context"
	"errors"
	"fmt"

	"github.com/tetratelabs/wazero/api"
)

// AllocAndWrite allocates guest memory via alloc function and writes data into it.
func AllocAndWrite(
	ctx context.Context,
	mod api.Module,
	alloc api.Function,
	data []byte,
) (uint32, error) {
	results, err := alloc.Call(ctx, uint64(len(data)))
	if err != nil {
		return 0, fmt.Errorf("alloc failed: %w", err)
	}
	ptr := api.DecodeU32(results[0])
	if !mod.Memory().Write(ptr, data) {
		return 0, errors.New("memory write failed: bounds exceeded")
	}

	return ptr, nil
}

// CallExecute invokes the plugin's Execute function with pointer and length.
func CallExecute(ctx context.Context, exec api.Function, ptr, length uint32) (uint64, error) {
	results, err := exec.Call(ctx, uint64(ptr), uint64(length))
	if err != nil {
		return 0, fmt.Errorf("execution failed: %w", err)
	}
	if len(results) < 1 {
		return 0, errors.New("invalid execution result")
	}

	return results[0], nil
}

// ReadResult reads length bytes from guest memory at ptr.
func ReadResult(mod api.Module, ptr, length uint32) ([]byte, error) {
	data, ok := mod.Memory().Read(ptr, length)
	if !ok {
		return nil, errors.New("memory read failed: bounds exceeded")
	}

	return data, nil
}
