//go:build !wasm

// This package just contains stubs for the WASM functions. to avoid linter compains.
package logic

func wasmEncryptUnderLMK(
	_, _, _, _, _ uint32,
) uint64 {
	return 0
}

func wasmDecryptUnderLMK(
	_, _, _, _, _ uint32,
) uint64 {
	return 0
}

func wasmLogInfo(_ string) {}

func wasmLogError(_ string) {}

func wasmLogDebug(_ string) {}

func wasmRandomKey(_ uint32) uint64 { return 0 }
