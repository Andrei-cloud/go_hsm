// Package hsmplugin provides helper functions for WASM plugins.
package hsmplugin

import (
	"unsafe"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/tetratelabs/wazero/api"
)

type Buffer uint64

func ToBuffer(data []byte) Buffer {
	if len(data) == 0 {
		return Buffer(0)
	}

	return Buffer(packResult(writeBytes(data)))
}

func (b Buffer) ToBytes() []byte {
	if b == 0 {
		return nil
	}

	ptr, length := unpackResult(uint64(b))
	if length == 0 {
		return nil
	}

	// Read bytes from WASM memory.
	return ReadBytes(ptr, length)
}

func (b Buffer) AddressSize() (uint32, uint32) {
	if b == 0 {
		return 0, 0
	}

	ptr, length := unpackResult(uint64(b))
	if length == 0 {
		return 0, 0
	}

	return ptr, length
}

// ReadBytes reads length bytes from WASM linear memory at ptr.
//
//nolint:gosec // allow unsafe pointer usage.
func ReadBytes(ptr, length uint32) []byte {
	// Directly map to WASM memory.
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

// packResult combines a pointer and a length into a single uint64 result.
func packResult(ptr, length uint32) uint64 {
	return uint64(ptr)<<32 | uint64(length)
}

// UnpackResult splits a combined uint64 value into pointer and length.
func unpackResult(val uint64) (uint32, uint32) {
	ptr := api.DecodeU32(val >> 32)
	length := api.DecodeU32(val)
	return ptr, length
}

// WriteError allocates and writes an error code for the specified command and returns the packed result.
func WriteError(cmd string) Buffer {
	b := cmd[1]
	if b == 'Z' {
		b = 'A'
	} else {
		b++
	}

	errCode := "Err: " + cmd[:1] + string(b) + errorcodes.Err68.CodeOnly()

	return ToBuffer([]byte(errCode))
}
