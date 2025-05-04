// Package logic provides business logic for HSM commands.
package logic

import (
	"errors"
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteBU processes the BU payload and returns response bytes.
// BU command generates a Key Check Value for a provided key.
// Format: KeyTypeCode(2) + KeyLengthFlag(1) + Key.
func ExecuteBU(
	input []byte,
	decryptUnderLMK func([]byte) ([]byte, error),
	_ func([]byte) ([]byte, error),
	logFn func(string),
) ([]byte, error) {
	if len(input) < 3 {
		return nil, errorcodes.Err15
	}

	// Parse input fields
	keyTypeCode := input[0:2]
	keyLengthFlag := input[2]
	remainder := input[3:]

	logFn(
		fmt.Sprintf(
			"BU command input - key type: %s, length flag: %c",
			string(keyTypeCode),
			keyLengthFlag,
		),
	)

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

	logFn(fmt.Sprintf("BU processing encrypted key (hex): %s", string(keyHex)))

	// Convert encrypted key from hex to binary
	encryptedKey, err := cryptoutils.B2Raw(keyHex)
	if err != nil {
		return nil, errors.Join(errors.New("invalid key format"), err)
	}

	// Decrypt key under LMK
	clearKey, err := decryptUnderLMK(encryptedKey)
	if err != nil {
		return nil, errors.Join(errors.New("failed to decrypt key under lmk"), err)
	}

	logFn(fmt.Sprintf("BU clear key (hex): %s", cryptoutils.Raw2Str(clearKey)))

	// Verify key parity after decryption
	if !cryptoutils.CheckKeyParity(clearKey) {
		logFn("BU key parity check failed")

		return nil, errorcodes.Err01
	}

	// Calculate 16-byte KCV using clear key
	kcv, err := cryptoutils.KeyCV(cryptoutils.Raw2B(clearKey), 16)
	if err != nil {
		return nil, errors.Join(errors.New("failed to calculate kcv"), err)
	}

	logFn(fmt.Sprintf("BU calculated KCV: %s", string(kcv)))

	// Format successful response
	resp := []byte("BV00")
	resp = append(resp, kcv...)

	return resp, nil
}
