// Package logic provides business logic for HSM commands.
package logic

import "github.com/andrei-cloud/go_hsm/pkg/hsmplugin"

//go:wasm-module env
//export EncryptUnderLMK
func wasmEncryptUnderLMK(ptr, length uint32) uint64

//go:wasm-module env
//export DecryptUnderLMK
func wasmDecryptUnderLMK(ptr, length uint32) uint64

//go:wasm-module env
//export log_debug
func wasmLogToHost(s string)

// encryptUnderLMK calls the host export to encrypt data under LMK.
func encryptUnderLMK(data []byte) ([]byte, error) {
	buf := hsmplugin.ToBuffer(data)
	r := wasmEncryptUnderLMK(buf.AddressSize())

	return hsmplugin.Buffer(r).ToBytes(), nil
}

// decryptUnderLMK calls the host export to decrypt data under LMK.
func decryptUnderLMK(data []byte) ([]byte, error) {
	buf := hsmplugin.ToBuffer(data)
	r := wasmDecryptUnderLMK(buf.AddressSize())

	return hsmplugin.Buffer(r).ToBytes(), nil
}

// logDebug invokes the host log_debug export.
func logDebug(msg string) {
	wasmLogToHost(msg)
}
