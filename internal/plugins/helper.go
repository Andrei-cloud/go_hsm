// Package plugins provides helper routines for allocating and executing WASM plugin memory operations.
package plugins

import (
	"context"
	"errors"
	"fmt"

	"github.com/andrei-cloud/go_hsm/pkg/hsmplugin"
	"github.com/tetratelabs/wazero/api"
)

// AllocBuffer allocates guest memory via the wasm Alloc export and writes
// the given host-side data slice into the guest's linear memory, returning the pointer address.
func AllocBuffer(
	ctx context.Context,
	mod api.Module,
	alloc api.Function,
	data []byte,
) (uint32, error) {
	length := uint32(len(data))
	if length == 0 {
		return 0, errors.New("buffer length is zero")
	}

	results, err := alloc.Call(ctx, uint64(length))
	if err != nil {
		return 0, fmt.Errorf("alloc failed: %w", err)
	}
	if len(results) < 1 {
		return 0, errors.New("alloc returned no results")
	}

	// The wasm Alloc returns a packed u64 ptr<<32|len, so high 32 bits is ptr.
	ptr := api.DecodeU32(results[0] >> 32)

	if !mod.Memory().Write(ptr, data) {
		return 0, errors.New("memory write failed: bounds exceeded")
	}

	return ptr, nil
}

// CallExecute invokes the plugin's Execute function with pointer and length and returns the packed uint64 result.
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

// ReadBuffer reads bytes from guest memory at the address represented by buf and returns them as a byte slice.
func ReadBuffer(mod api.Module, buf hsmplugin.Buffer) ([]byte, error) {
	data, ok := mod.Memory().Read(buf.AddressSize())
	if !ok {
		return nil, errors.New("memory read failed: bounds exceeded")
	}

	return data, nil
}

// ReadBufferToPool reads bytes from guest memory at the address represented by buf
// and returns them using a buffer from the provided pool.
// This optimized version avoids double-copying where possible by using direct access
// to memory when available.
func ReadBufferToPool(
	mod api.Module,
	buf hsmplugin.Buffer,
	pool *hsmplugin.BufferPool,
) ([]byte, error) {
	ptr, size := buf.AddressSize()
	if size == 0 {
		return nil, nil
	}

	// Read memory directly - this is a view into WASM memory, not a copy
	data, ok := mod.Memory().Read(ptr, size)
	if !ok {
		return nil, errors.New("memory read failed: bounds exceeded")
	}

	// Get a buffer from the pool
	result := pool.Get(int(size))

	// Copy the data into our pooled buffer
	// This is unavoidable as we need to preserve the data after returning from WASM
	copy(result, data)

	return result, nil
}
