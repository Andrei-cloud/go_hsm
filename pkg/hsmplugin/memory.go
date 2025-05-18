// Package hsmplugin provides WASM memory management and helper utilities for plugin wrappers.
package hsmplugin

import (
	"unsafe"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/tetratelabs/wazero/api"
)

// Buffer represents a pointer and length packed in a uint64 for WASM memory operations.
//
// The high 32 bits hold the pointer and the low 32 bits hold the length. This encoding is used
// because the WASM ABI (as used by go_hsm) returns a single 64-bit value from guest functions,
// and Go code can extract the pointer and length using UnpackResult. This approach is necessary
// for compatibility with WASM's single-value return, but may be replaced by returning two uint32s
// in future ABIs for clarity and simplicity.
type Buffer uint64

// ToBuffer allocates memory for data in WASM linear memory and returns a Buffer referencing it.
func ToBuffer(data []byte) Buffer {
	if len(data) == 0 {
		return Buffer(0)
	}

	return Buffer(PackResult(writeBytes(data)))
}

// ToBytes reads and returns the byte slice from WASM memory pointed to by Buffer.
func (b Buffer) ToBytes() []byte {
	if b == 0 {
		return nil
	}

	ptr, length := UnpackResult(uint64(b))
	if length == 0 {
		return nil
	}

	// Read bytes from WASM memory.
	return ReadBytes(ptr, length)
}

// AddressSize returns the pointer and length stored within the Buffer.
func (b Buffer) AddressSize() (uint32, uint32) {
	if b == 0 {
		return 0, 0
	}

	ptr, length := UnpackResult(uint64(b))
	if length == 0 {
		return 0, 0
	}

	return ptr, length
}

// ReadBytes reads length bytes from WASM linear memory at ptr and returns them as a slice.
//
//nolint:gosec // allow unsafe pointer usage.
func ReadBytes(ptr, length uint32) []byte {
	// Directly map to WASM memory. Use uintptr conversion as required by Go 1.17+.
	if ptr == 0 || length == 0 {
		return nil
	}

	return unsafe.Slice((*byte)(unsafe.Pointer(uintptr(ptr))), uintptr(length))
}

// writeBytes writes data into WASM linear memory at ptr.
func writeBytes(data []byte) (uint32, uint32) {
	if len(data) == 0 {
		return 0, 0
	}

	// get the low 32 bits of the wasm-memory pointer to data[0].
	ptr := uint32(uintptr(unsafe.Pointer(&data[0])))

	return ptr, uint32(len(data))
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

// WriteError allocates and writes an error response for the specified command.
// If err is of type HSMError, formats response as "<cmd><code>", otherwise uses generic error 68.
func WriteError(cmd string, err error) Buffer {
	var errCode string
	if hsmErr, ok := err.(errorcodes.HSMError); ok {
		errCode = hsmErr.CodeOnly()
	} else {
		errCode = errorcodes.Err68.CodeOnly()
	}

	// Format error response: increment command code + error code
	nextCmd := cmd[0:1]
	if len(cmd) > 1 {
		b := cmd[1]
		if b == 'Z' {
			b = 'A'
		} else {
			b++
		}
		nextCmd += string(b)
	}

	return ToBuffer([]byte(nextCmd + errCode))
}
