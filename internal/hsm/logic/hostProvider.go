package logic

import (
	"crypto/des"
	"errors"

	"github.com/andrei-cloud/go_hsm/pkg/common"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
	"github.com/andrei-cloud/go_hsm/pkg/hsmplugin"
)

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
func encryptUnderLMK(plainKey []byte, keyType string, schemeTag byte) ([]byte, error) {
	// map Z scheme to X9.17 for single-length DES under LMK
	if schemeTag == 'Z' {
		schemeTag = 'X'
	}

	plainKeyPtr, plainKeyLen := hsmplugin.ToBuffer(plainKey).AddressSize()
	keyTypeStrPtr, keyTypeStrLen := hsmplugin.ToBuffer([]byte(keyType)).AddressSize()

	r := wasmEncryptUnderLMK(
		plainKeyPtr,
		plainKeyLen,
		keyTypeStrPtr,
		keyTypeStrLen,
		uint32(schemeTag),
	)
	if r == 0 {
		return nil, errors.New("failed to encrypt key under LMK")
	}

	// read bytes from WASM memory and make a deep copy
	buf := hsmplugin.Buffer(r).ToBytes()
	copyBuf := append([]byte(nil), buf...)

	return copyBuf, nil
}

// decryptUnderLMK calls the host export to decrypt data under LMK.
func decryptUnderLMK(encryptedKey []byte, keyType string, schemeTag byte) ([]byte, error) {
	// map Z scheme to X9.17 for single-length DES under LMK
	if schemeTag == 'Z' {
		schemeTag = 'X'
	}

	encryptedKeyPtr, encryptedKeyLen := hsmplugin.ToBuffer(encryptedKey).AddressSize()
	keyTypeStrPtr, keyTypeStrLen := hsmplugin.ToBuffer([]byte(keyType)).AddressSize()
	r := wasmDecryptUnderLMK(
		encryptedKeyPtr,
		encryptedKeyLen,
		keyTypeStrPtr,
		keyTypeStrLen,
		uint32(schemeTag),
	)
	if r == 0 {
		return nil, errors.New("failed to decrypt key under LMK")
	}

	// read bytes from WASM memory and make a deep copy
	buf := hsmplugin.Buffer(r).ToBytes()
	copyBuf := append([]byte(nil), buf...)

	return copyBuf, nil
}

// logInfo invokes the host log_info export.
func logInfo(msg string) {
	wasmLogInfo(common.FormatData([]byte(msg)))
}

// logError invokes the host log_error export.
func logError(msg string) {
	wasmLogError(common.FormatData([]byte(msg)))
}

// logDebug invokes the host log_debug export.
func logDebug(msg string) {
	wasmLogDebug(common.FormatData([]byte(msg)))
}

// getKeyLength returns the key length in bytes based on the encryption scheme tag.
func getKeyLength(scheme byte) int {
	switch scheme {
	case 'U', 'X':
		return 16 // double-length DES
	case 'T', 'Y':
		return 24 // triple-length DES
	default:
		return 8 // single-length DES (Z or blank)
	}
}

// encryptKeyUnderZMK encrypts clearKey using the provided ZMK.
// It assumes the ZMK key type is "000" and derives the scheme ('U' or 'T') from the length of zmkBytes.
func encryptKeyUnderZMK(clearKey, zmkBytes []byte) ([]byte, error) {
	const zmkKeyType = "000" // Standard Thales key type for ZMK.
	var zmkSchemeTag byte

	switch len(zmkBytes) {
	case 16: // Double-length key.
		zmkSchemeTag = 'U'
	case 24: // Triple-length key.
		zmkSchemeTag = 'T'
	default:
		return nil, errors.New("invalid zmk length, must be 16 or 24 bytes")
	}

	rawZmk, err := LMKProviderInstance.DecryptUnderLMK(zmkBytes, zmkKeyType, zmkSchemeTag)
	if err != nil {
		return nil, errors.Join(errors.New("decrypt zmk"), err)
	}

	zmkBlock, err := des.NewTripleDESCipher(cryptoutils.PrepareTripleDESKey(rawZmk))
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
