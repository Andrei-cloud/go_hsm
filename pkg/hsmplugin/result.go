// Package hsmplugin provides helper functions for WASM plugins.
package hsmplugin

import "github.com/andrei-cloud/go_hsm/internal/errorcodes"

// PackResult combines a pointer and a length into a single uint64 result.
func PackResult(ptr, length uint32) uint64 {
	return uint64(ptr)<<32 | uint64(length)
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
	data := []byte(errCode)
	ptr := Alloc(uint32(len(data)))
	WriteBytes(ptr, data)

	return PackResult(ptr, uint32(len(data)))
}
