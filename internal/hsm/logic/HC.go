package logic

import (
	"crypto/des"
	"encoding/hex"
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteHC generates a TMK, TPK or PVK Variant LMK key, ignoring PCI compliance enforcement.
func ExecuteHC(input []byte) ([]byte, error) {
	logInfo("HC: starting key generation")

	// Fast fail: must have at least enough for minimal key (16 hex) + 'HC' (2)
	if len(input) < 18 {
		logError("HC: input too short for key and command code")
		return nil, errorcodes.Err15
	}

	inputKeyScheme := input[0]
	var keyLen int
	var keyHexLen int
	var encKeyHex string

	logInfo("HC: processing input key scheme")
	logDebug(fmt.Sprintf("HC: input key scheme: %c", inputKeyScheme))

	if inputKeyScheme == 'U' || inputKeyScheme == 'T' || inputKeyScheme == 'X' {
		keyLen = getKeyLength(inputKeyScheme)
		keyHexLen = keyLen * 2
		logDebug(fmt.Sprintf("HC: key length: %d bytes (%d hex chars)", keyLen, keyHexLen))

		if len(input) < 1+keyHexLen+2 {
			logError("HC: insufficient data for key with scheme")
			return nil, errorcodes.Err15
		}
		encKeyHex = string(input[1 : 1+keyHexLen])
		input = input[1+keyHexLen:]
	} else {
		// No scheme provided, treat as paired single-length components
		logInfo("HC: processing key as paired single-length components")
		inputKeyScheme = 'X'
		keyHexLen = 16

		if len(input) < keyHexLen+2 {
			logError("HC: insufficient data for paired single-length key")
			return nil, errorcodes.Err15
		}
		encKeyHex = string(input[:keyHexLen])
		input = input[keyHexLen:]
	}

	// Accept and skip optional fields after 'HC' (delimiter, key schemes, reserved, LMK id, etc.)
	if len(input) > 0 && input[0] == ';' {
		logInfo("HC: processing optional fields")
		input = input[1:]
		// Only skip up to 3 optional fields if present, but do not require them
		for i := 0; i < 3; i++ {
			if len(input) == 0 {
				break
			}
			logDebug(fmt.Sprintf("HC: skipping optional field %d", i+1))
			input = input[1:]
		}
	}

	if len(input) > 0 && input[0] == '%' {
		logInfo("HC: processing LMK identifier")
		if len(input) >= 3 {
			_ = input[3:]
		} else {
			logDebug("HC: incomplete LMK identifier, skipping")
			_ = input[len(input):] // skip to end
		}
	}

	logInfo("HC: decoding input key")
	encKeyBytes, err := hex.DecodeString(encKeyHex)
	if err != nil {
		logError("HC: invalid key hex format")
		return nil, errorcodes.Err15
	}
	logDebug(fmt.Sprintf("HC: encoded key value: %x", encKeyBytes))

	const keyType = "002"
	logInfo("HC: decrypting key under LMK")
	clearKey, err := LMKProviderInstance.DecryptUnderLMK(encKeyBytes, keyType, inputKeyScheme)
	if err != nil {
		logError("HC: key decryption failed")
		return nil, errorcodes.Err10
	}

	logInfo("HC: verifying key parity")
	if !cryptoutils.CheckKeyParity(clearKey) {
		logError("HC: key parity check failed")
		return nil, errorcodes.Err10
	}

	genKeyLen := getKeyLength(inputKeyScheme)
	logInfo("HC: generating new random key")
	newKey, err := LMKProviderInstance.RandomKey(genKeyLen)
	if err != nil {
		logError("HC: random key generation failed")
		return nil, errorcodes.Err20
	}

	logInfo("HC: encrypting generated key under LMK")
	lmkEncryptedKey, err := LMKProviderInstance.EncryptUnderLMK(newKey, keyType, inputKeyScheme)
	if err != nil {
		logError("HC: key encryption under LMK failed")
		return nil, errorcodes.Err20
	}

	logInfo("HC: encrypting generated key under TMK")
	tmkEncryptedKey := make([]byte, len(newKey))
	block := prepareTripleDESKey(clearKey)
	cipher, err := des.NewTripleDESCipher(block)
	if err != nil {
		logError("HC: failed to create TMK cipher")
		return nil, errorcodes.Err20
	}

	for i := 0; i < len(newKey); i += 8 {
		cipher.Encrypt(tmkEncryptedKey[i:i+8], newKey[i:i+8])
	}

	logInfo("HC: formatting response")
	resp := []byte("HD00")
	resp = appendEncryptedKeyToResponse(resp, inputKeyScheme, tmkEncryptedKey)
	resp = appendEncryptedKeyToResponse(resp, inputKeyScheme, lmkEncryptedKey)

	logDebug(fmt.Sprintf("HC: response value: %x", resp))

	return resp, nil
}
