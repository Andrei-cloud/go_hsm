package logic

import (
	"crypto/des"
	"encoding/hex"
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

const (
	zmkKeyType      = "000" // ZMK, LMK pair 04-05
	keyTypeLength   = 3
	kcvDigits       = 6
	singleKeyLength = 8
	doubleKeyLength = 16
	tripleKeyLength = 24
)

// readZMK reads a ZMK under LMK (16 hex digits, or 'U' and 32, or 'T' and 48),
// decrypts it and checks its parity. It returns the clear ZMK and what follows.
func readZMK(cmd string, data []byte) ([]byte, []byte, error) {
	scheme, encryptedZMK, rest, err := readKeyUnderLMK(data)
	if err != nil {
		logError(cmd + ": invalid ZMK")
		return nil, nil, err
	}

	clearZMK, err := LMKProviderInstance.DecryptUnderLMK(encryptedZMK, zmkKeyType, scheme)
	if err != nil {
		logError(cmd + ": ZMK decryption failed")
		return nil, nil, errorcodes.Err68
	}

	if !cryptoutils.CheckKeyParity(clearZMK) {
		logError(cmd + ": ZMK parity error")
		return nil, nil, errorcodes.Err10
	}

	return clearZMK, rest, nil
}

// zoneSchemeLength is the key length in bytes that a key-under-ZMK scheme tag
// carries: 'Z' (or no tag) single, 'X' double and 'Y' triple length, each
// encrypted under the ZMK in ECB mode (ANSI X9.17). The Thales variant forms
// 'U' and 'T' under a ZMK are not supported.
func zoneSchemeLength(scheme byte) (int, error) {
	switch scheme {
	case 'Z':
		return singleKeyLength, nil
	case 'X':
		return doubleKeyLength, nil
	case 'Y':
		return tripleKeyLength, nil
	}

	return 0, errorcodes.Err26
}

// readKeyUnderZMK reads a key under the ZMK: 16 hex digits, or 'X' and 32, or
// 'Y' and 48. It returns the key bytes and what follows.
func readKeyUnderZMK(cmd string, data []byte) ([]byte, []byte, error) {
	if len(data) == 0 {
		logError(cmd + ": missing key under ZMK")
		return nil, nil, errorcodes.Err15
	}

	scheme, start := byte('Z'), 0
	if data[0] < '0' || data[0] > 'F' || (data[0] > '9' && data[0] < 'A') {
		scheme, start = data[0], 1
	}

	length, err := zoneSchemeLength(scheme)
	if err != nil {
		logError(cmd + ": unsupported key scheme under ZMK")
		return nil, nil, err
	}

	end := start + 2*length
	if len(data) < end {
		logError(cmd + ": key under ZMK too short")
		return nil, nil, errorcodes.Err15
	}

	key, err := hex.DecodeString(string(data[start:end]))
	if err != nil {
		logError(cmd + ": key under ZMK is not hex")
		return nil, nil, errorcodes.Err15
	}

	return key, data[end:], nil
}

// underZMK encrypts or decrypts key under the clear ZMK in ECB mode.
func underZMK(zmk, key []byte, encrypt bool) ([]byte, error) {
	block, err := des.NewTripleDESCipher(cryptoutils.PrepareTripleDESKey(zmk))
	if err != nil {
		return nil, fmt.Errorf("zmk cipher: %w", err)
	}

	out := make([]byte, len(key))
	for i := 0; i < len(key); i += singleKeyLength {
		if encrypt {
			block.Encrypt(out[i:i+singleKeyLength], key[i:i+singleKeyLength])
		} else {
			block.Decrypt(out[i:i+singleKeyLength], key[i:i+singleKeyLength])
		}
	}

	return out, nil
}

// isAllZero is whether every byte of key is zero.
func isAllZero(key []byte) bool {
	for _, b := range key {
		if b != 0 {
			return false
		}
	}

	return true
}

// readLMKScheme reads the one-character key scheme under LMK ('Z', 'U' or 'T')
// that must carry a key of keyLength bytes.
func readLMKScheme(cmd string, data []byte, keyLength int) (byte, error) {
	if len(data) < 1 {
		logError(cmd + ": missing key scheme under LMK")
		return 0, errorcodes.Err15
	}

	scheme := data[0]
	if scheme != 'Z' && scheme != 'U' && scheme != 'T' {
		logError(cmd + ": invalid key scheme under LMK")
		return 0, errorcodes.Err26
	}

	if getKeyLength(scheme) != keyLength {
		logError(cmd + ": key length does not match the key scheme under LMK")
		return 0, errorcodes.Err27
	}

	return scheme, nil
}

// readZoneScheme reads the one-character key scheme under ZMK ('Z', 'X' or
// 'Y') that must carry a key of keyLength bytes.
func readZoneScheme(cmd string, data []byte, keyLength int) (byte, error) {
	if len(data) < 1 {
		logError(cmd + ": missing key scheme under ZMK")
		return 0, errorcodes.Err15
	}

	scheme := data[0]

	length, err := zoneSchemeLength(scheme)
	if err != nil {
		logError(cmd + ": unsupported key scheme under ZMK")
		return 0, err
	}

	if length != keyLength {
		logError(cmd + ": key length does not match the key scheme under ZMK")
		return 0, errorcodes.Err27
	}

	return scheme, nil
}
