package main

import (
	"unsafe"

	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// firmwareVersion is the HSM firmware version.
const firmwareVersion = "1.0.0"

//export Execute
func Execute(ptr uint32, length uint32) uint64 {
	// build response: ND + error code 00 + LMK Check Value + firmwareVersion.
	lmkHex := "0123456789ABCDEF0123456789ABCDEF"
	kcv, _ := cryptoutils.KeyCV([]byte(lmkHex), 16)
	resp := []byte("ND00")
	resp = append(resp, kcv...)
	resp = append(resp, []byte(firmwareVersion)...)
	for i, b := range resp {
		*(*byte)(unsafe.Pointer(uintptr(ptr) + uintptr(i))) = b
	}
	return uint64(ptr)<<32 | uint64(len(resp))
}

func main() {}
