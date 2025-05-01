// Package hsmplugin provides helper functions for WASM plugins.
package hsmplugin

import "unsafe"

// ReadBytes reads length bytes from WASM linear memory at ptr.
//
//nolint:gosec // allow unsafe pointer usage.
func ReadBytes(ptr, length uint32) []byte {
	return (*[1 << 30]byte)(unsafe.Pointer(uintptr(ptr)))[:length:length]
}

// WriteBytes writes data into WASM linear memory at ptr.
func WriteBytes(ptr uint32, data []byte) {
	dest := ReadBytes(ptr, uint32(len(data)))
	copy(dest, data)
}
