// nolint:all // wasm specific
// Package logic provides business logic for HSM commands.
package logic

import (
	"crypto/des"
	"errors"

	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
	"github.com/andrei-cloud/go_hsm/pkg/hsmplugin"
)

//go:wasm-module env
//export EncryptUnderLMK
func wasmEncryptUnderLMK(ptr, length uint32) uint64

//go:wasm-module env
//export DecryptUnderLMK
func wasmDecryptUnderLMK(ptr, length uint32) uint64

//go:wasm-module env
//export log_debug
func wasmLogToHost(s string)

//go:wasm-module env
//export RandomKey
func wasmRandomKey(length uint32) uint64

func randomKey(length int) ([]byte, error) {
	buf := wasmRandomKey(uint32(length))
	if buf == 0 {
		return nil, errors.New("failed to generate random key")
	}

	// Convert the buffer to a byte slice
	key := hsmplugin.Buffer(buf).ToBytes()
	if len(key) != length {
		return nil, errors.New("generated key length mismatch")
	}

	return key, nil
}

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

// getKeyLength returns the key length in bytes based on the scheme.
func getKeyLength(scheme byte) int {
	if scheme == 'T' {
		return 24 // Triple length
	}
	return 16 // Double length 'U' scheme
}

// prepareTripleDESKey extends double length key to triple length if needed.
func prepareTripleDESKey(key []byte) []byte {
	if len(key) == 16 {
		fullKey := make([]byte, 24)
		copy(fullKey, key)
		copy(fullKey[16:], key[:8])
		return fullKey
	}
	return key
}

// encryptKeyUnderZMK encrypts clearKey using the provided ZMK.
func encryptKeyUnderZMK(clearKey []byte, zmkBytes []byte) ([]byte, error) {
	rawZmk, err := decryptUnderLMK(zmkBytes)
	if err != nil {
		return nil, errors.Join(errors.New("decrypt zmk"), err)
	}

	zmkBlock, err := des.NewTripleDESCipher(prepareTripleDESKey(rawZmk))
	if err != nil {
		return nil, errors.Join(errors.New("create zmk cipher"), err)
	}

	// Encrypt under ZMK
	zmkEncryptedKey := make([]byte, len(clearKey))
	for i := 0; i < len(clearKey); i += 8 {
		zmkBlock.Encrypt(zmkEncryptedKey[i:i+8], clearKey[i:i+8])
	}

	return zmkEncryptedKey, nil
}

// appendEncryptedKeyToResponse appends the encrypted key to response with proper formatting.
func appendEncryptedKeyToResponse(resp []byte, keyScheme byte, encryptedKey []byte) []byte {
	resp = append(resp, keyScheme)
	keyLength := getKeyLength(keyScheme)
	return append(resp, cryptoutils.Raw2B(encryptedKey[:keyLength])...)
}
