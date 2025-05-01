// Package hsmplugin provides helper functions for WASM plugins.
package hsmplugin

var nextPtr uint32

// ResetAllocator resets the allocator to the initial memory offset.
func ResetAllocator() {
	nextPtr = 8
}

// Alloc allocates n bytes with 8-byte alignment and returns the starting pointer.
func Alloc(n uint32) uint32 {
	ptr := nextPtr
	padding := (8 - n%8) % 8
	nextPtr += n + padding

	return ptr
}

// Free releases the memory at ptr.
// Currently a no-op.
func Free(ptr uint32) {
	_ = ptr
}
