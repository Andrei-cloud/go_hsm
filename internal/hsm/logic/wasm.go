//go:build wasm

package logic

//go:wasm-module env
//export EncryptUnderLMK
func wasmEncryptUnderLMK(
	plainKeyPtr, plainKeyLen, keyTypeStrPtr, keyTypeStrLen, schemeTagRaw uint32,
) uint64

//go:wasm-module env
//export DecryptUnderLMK
func wasmDecryptUnderLMK(
	encryptedKeyPtr, encryptedKeyLen, keyTypeStrPtr, keyTypeStrLen, schemeTagRaw uint32,
) uint64

//go:wasm-module env
//export log_info
func wasmLogInfo(s string)

//go:wasm-module env
//export log_error
func wasmLogError(s string)

//go:wasm-module env
//export log_debug
func wasmLogDebug(s string)

//go:wasm-module env
//export RandomKey
func wasmRandomKey(length uint32) uint64
