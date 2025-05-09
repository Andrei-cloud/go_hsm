// Package logic provides business logic for HSM commands.
package logic

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteBU processes the BU payload and returns response bytes.
// BU command generates a Key Check Value for a provided key.
// Format: KeyTypeCode(2) + KeyLengthFlag(1) + Key.
func ExecuteBU(input []byte) ([]byte, error) {
	if len(input) < 3 {
		return nil, errorcodes.Err15
	}

	// Parse input fields
	keyTypeCode := string(input[0:2])
	keyLengthFlag := input[2]
	remainder := input[3:]

	logDebug(
		fmt.Sprintf(
			"BU command input - key type: %s, length flag: %c", keyTypeCode, keyLengthFlag,
		),
	)

	//ketypecode - '00' – '9E': this field indicates a 2-digit Key Type Code
	//(identical to the regular 3-digit Key Type Code but without the
	//middle digit) need to be converted to a 3-digit Key Type Code
	// by inserting a '0' in the middle.
	if keyTypeCode[0] < '0' || keyTypeCode[0] > '9' ||
		keyTypeCode[1] < '0' || keyTypeCode[1] > 'D' {
		return nil, errorcodes.Err26
	}
	keyType := fmt.Sprintf("%c0%c", keyTypeCode[0], keyTypeCode[1])
	logDebug(fmt.Sprintf("BU key type: %s", keyType))

	// For U scheme, expect key length of 33 (flag + 32 hex chars)
	if len(remainder) < 33 {
		return nil, errorcodes.Err15
	}

	keyScheme := remainder[0]
	if keyScheme != 'U' && keyScheme != 'T' {
		return nil, errorcodes.Err26
	}
	// Strip the key scheme flag
	keyHex := remainder[1:]

	logDebug(fmt.Sprintf("BU processing encrypted key (hex): %s", string(keyHex)))

	// Convert encrypted key from hex to binary
	encryptedKey, err := hex.DecodeString(string(keyHex))
	if err != nil {
		return nil, errors.Join(errors.New("invalid key format"), err)
	}

	logDebug(fmt.Sprintf("BU encrypted key (hex): %s", cryptoutils.Raw2Str(encryptedKey)))

	// Decrypt key under LMK
	clearKey, err := decryptUnderLMK(encryptedKey, keyType, keyScheme)
	if err != nil {
		return nil, errors.Join(errors.New("failed to decrypt key under lmk"), err)
	}

	logDebug(fmt.Sprintf("BU clear key (hex): %s", cryptoutils.Raw2Str(clearKey)))

	// Verify key parity after decryption
	if !cryptoutils.CheckKeyParity(clearKey) {
		logDebug("BU key parity check failed")

		return nil, errorcodes.Err01
	}

	// Calculate 16-byte KCV using clear key
	kcv, err := cryptoutils.KeyCV(cryptoutils.Raw2B(clearKey), 16)
	if err != nil {
		return nil, errors.Join(errors.New("failed to calculate kcv"), err)
	}

	logDebug(fmt.Sprintf("BU calculated KCV: %s", string(kcv)))

	// Format successful response
	resp := []byte("BV00")
	rest := append(resp, kcv...)

	return rest, nil
}
