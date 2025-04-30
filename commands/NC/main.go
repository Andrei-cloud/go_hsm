package main

import (
	"unsafe"

	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// Memory layout:
// [0-7]: reserved
// [8+]: available for allocation.
var nextPtr uint32 = 8

//export Alloc
func Alloc(size uint32) uint32 {
	ptr := nextPtr
	nextPtr += size + (8 - size%8) // Align to 8-byte boundary.
	return ptr
}

//export Free
func Free(_ uint32) {
	// No-op for this implementation
}

//export Execute
func Execute(ptr, length uint32) uint64 {
	nextPtr = 8

	// Input validation
	if length < 48 {
		// Input too short for LMK hex, return error.

		return makeErrorResponse()
	}

	// The input is already in WASM memory at ptr
	// No need to copy, just slice the memory.
	lmkHex := getData(ptr, 48)
	firmware := getData(ptr+48, length-48)

	// Calculate KCV using the hex-encoded LMK
	kcv, err := cryptoutils.KeyCV(lmkHex, 16)
	if err != nil {
		return makeErrorResponse()
	}

	// Build success response: ND00 + KCV + firmware.
	resp := make([]byte, 0, 4+len(kcv)+len(firmware))
	resp = append(resp, []byte("ND00")...)
	resp = append(resp, kcv...)
	resp = append(resp, firmware...)

	// Write response to memory.
	outPtr := Alloc(uint32(len(resp)))
	putData(outPtr, resp)

	return uint64(outPtr)<<32 | uint64(len(resp))
}

func makeErrorResponse() uint64 {
	errResp := []byte("ND86")
	outPtr := Alloc(4)
	putData(outPtr, errResp)

	return uint64(outPtr)<<32 | 4
}

// getData gets a slice of data from WASM memory.
//
//go:inline
func getData(offset, length uint32) []byte {
	return (*[1 << 30]byte)(unsafe.Pointer(uintptr(offset)))[:length:length]
}

// putData writes data to WASM memory.
//
//go:inline
func putData(offset uint32, data []byte) {
	dest := getData(offset, uint32(len(data)))
	copy(dest, data)
}

func main() {}
