// Package hsmplugin provides helper functions for WASM plugins.
package hsmplugin

import (
	"unsafe"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/tetratelabs/wazero/api"
)

// ReadBytes reads length bytes from WASM linear memory at ptr.
//
//nolint:gosec // allow unsafe pointer usage.
func ReadBytes(ptr, length uint32) []byte {
	// Directly map to WASM memory.
	return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), uintptr(length))
}

// WriteBytes writes data into WASM linear memory at ptr.
func WriteBytes(data []byte) (uint32, uint32) {
	if len(data) == 0 {
		return 0, 0
	}

	address := uint32(uintptr(unsafe.Pointer(&data[0])) << 32)
	length := uint32(len(data))

	return address, length
}

// PackResult combines a pointer and a length into a single uint64 result.
func PackResult(ptr, length uint32) uint64 {
	return uint64(ptr)<<32 | uint64(length)
}

// UnpackResult splits a combined uint64 value into pointer and length.
func UnpackResult(val uint64) (uint32, uint32) {
	ptr := api.DecodeU32(val >> 32)
	length := api.DecodeU32(val)
	return ptr, length
}

// WriteError allocates and writes an error code for the specified command and returns the packed result.
func WriteError(cmd string) uint64 {
	b := cmd[1]
	if b == 'Z' {
		b = 'A'
	} else {
		b++
	}

	errCode := cmd[:1] + string(b) + errorcodes.Err68.CodeOnly()

	return PackResult(WriteBytes([]byte(errCode)))
}
