package plugins

import (
	"context"
	"errors"
	"fmt"

	"github.com/andrei-cloud/go_hsm/pkg/hsmplugin"
	"github.com/tetratelabs/wazero/api"
)

// AllocBuffer allocates guest memory via alloc function and writes data into it.
func AllocBuffer(
	ctx context.Context,
	mod api.Module,
	alloc api.Function,
	buf hsmplugin.Buffer,
) (uint32, error) {
	_, length := buf.AddressSize()
	if length == 0 {
		return 0, errors.New("buffer length is zero")
	}
	results, err := alloc.Call(ctx, uint64(length))
	if err != nil {
		return 0, fmt.Errorf("alloc failed: %w", err)
	}
	ptr := api.DecodeU32(results[0])
	if !mod.Memory().Write(ptr, buf.ToBytes()) {
		return 0, errors.New("memory write failed: bounds exceeded")
	}

	return ptr, nil
}

// CallExecute invokes the plugin's Execute function with pointer and length.
func CallExecute(ctx context.Context, exec api.Function, ptr, length uint32) (uint64, error) {
	results, err := exec.Call(ctx, uint64(ptr)<<32|uint64(length))
	if err != nil {
		return 0, fmt.Errorf("execution failed: %w", err)
	}
	if len(results) < 1 {
		return 0, errors.New("invalid execution result")
	}

	return results[0], nil
}

// ReadBuffer reads length bytes from guest memory at ptr.
func ReadBuffer(mod api.Module, buf hsmplugin.Buffer) ([]byte, error) {
	data, ok := mod.Memory().Read(buf.AddressSize())
	if !ok {
		return nil, errors.New("memory read failed: bounds exceeded")
	}

	return data, nil
}
