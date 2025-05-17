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
	logDebug("HC: starting ExecuteHC")
	logDebug(fmt.Sprintf("HC: input length: %d", len(input)))

	// Fast fail: must have at least enough for minimal key (16 hex) + 'HC' (2)
	if len(input) < 18 {
		logDebug("HC: input too short for any valid key + HC")
		return nil, errorcodes.Err15
	}

	inputKeyScheme := input[0]
	var keyLen int
	var keyHexLen int
	var encKeyHex string

	logDebug(fmt.Sprintf("HC: inputKeyScheme: %c", inputKeyScheme))
	if inputKeyScheme == 'U' || inputKeyScheme == 'T' || inputKeyScheme == 'X' {
		keyLen = getKeyLength(inputKeyScheme)
		keyHexLen = keyLen * 2
		logDebug(fmt.Sprintf("HC: scheme provided, keyLen: %d, keyHexLen: %d", keyLen, keyHexLen))
		if len(input) < 1+keyHexLen+2 {
			logDebug("HC: not enough data for key+HC")
			return nil, errorcodes.Err15
		}
		encKeyHex = string(input[1 : 1+keyHexLen])
		logDebug(fmt.Sprintf("HC: encKeyHex: %s", encKeyHex))
		input = input[1+keyHexLen:]
	} else {
		logDebug("HC: no scheme provided, treat as paired single (PVK)")
		// No scheme provided, treat as paired single (PVK), key is 16 hex chars
		inputKeyScheme = 'X'
		keyLen = 8
		keyHexLen = 16
		if len(input) < keyHexLen+2 {
			logDebug("HC: not enough data for single-length key+HC")
			return nil, errorcodes.Err15
		}
		encKeyHex = string(input[:keyHexLen])
		logDebug(fmt.Sprintf("HC: encKeyHex: %s", encKeyHex))
		input = input[keyHexLen:]
	}

	// Accept and skip optional fields after 'HC' (delimiter, key schemes, reserved, LMK id, etc.)
	if len(input) > 0 && input[0] == ';' {
		logDebug("HC: found optional delimiter ';'")
		input = input[1:]
		// Only skip up to 3 optional fields if present, but do not require them
		for i := 0; i < 3; i++ {
			if len(input) == 0 {
				break
			}
			logDebug(fmt.Sprintf("HC: skipping optional field %d after ';'", i+1))
			input = input[1:]
		}
	}
	if len(input) > 0 && input[0] == '%' {
		logDebug("HC: found optional delimiter '%' for LMK id")
		if len(input) >= 3 {
			input = input[3:]
		} else {
			logDebug("HC: not enough data for LMK id after '%' delimiter, but skipping as optional")
			input = input[len(input):] // skip to end
		}
	}

	logDebug(fmt.Sprintf("HC: final encKeyHex for decode: %s", encKeyHex))
	encKeyBytes, err := hex.DecodeString(encKeyHex)
	if err != nil {
		logDebug("HC: failed to decode encKeyHex")
		return nil, errorcodes.Err15
	}

	const keyType = "002"
	clearKey, err := decryptUnderLMK(encKeyBytes, keyType, inputKeyScheme)
	if err != nil {
		logDebug("HC: failed to decrypt under LMK")
		return nil, errorcodes.Err10
	}
	logDebug(fmt.Sprintf("HC: clearKey: %x", clearKey))

	if !cryptoutils.CheckKeyParity(clearKey) {
		logDebug("HC: clearKey parity error")
		return nil, errorcodes.Err10
	}

	genKeyLen := getKeyLength(inputKeyScheme)
	logDebug(fmt.Sprintf("HC: generating new random key of length: %d", genKeyLen))
	newKey, err := randomKey(genKeyLen)
	if err != nil {
		logDebug("HC: failed to generate random key")
		return nil, errorcodes.Err20
	}
	logDebug(fmt.Sprintf("HC: newKey: %x", newKey))

	lmkEncryptedKey, err := encryptUnderLMK(newKey, keyType, inputKeyScheme)
	if err != nil {
		logDebug("HC: failed to encrypt newKey under LMK")
		return nil, errorcodes.Err20
	}
	logDebug(fmt.Sprintf("HC: lmkEncryptedKey: %x", lmkEncryptedKey))

	tmkEncryptedKey := make([]byte, len(newKey))
	block := prepareTripleDESKey(clearKey)
	cipher, err := des.NewTripleDESCipher(block)
	if err != nil {
		logDebug("HC: failed to create TDES cipher for TMK encryption")
		return nil, errorcodes.Err20
	}
	for i := 0; i < len(newKey); i += 8 {
		cipher.Encrypt(tmkEncryptedKey[i:i+8], newKey[i:i+8])
	}
	logDebug(fmt.Sprintf("HC: tmkEncryptedKey: %x", tmkEncryptedKey))

	resp := []byte("HD00")
	resp = appendEncryptedKeyToResponse(resp, inputKeyScheme, tmkEncryptedKey)
	resp = appendEncryptedKeyToResponse(resp, inputKeyScheme, lmkEncryptedKey)

	logDebug(fmt.Sprintf("HC: response: %x", resp))
	return resp, nil
}
