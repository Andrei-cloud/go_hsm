// Package logic provides business logic for HSM commands.
package logic

import (
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteA0 processes the A0 payload and returns response bytes.
// It always returns: "A1" + "00" + U|hex(newkey under lmk) [+ U|hex(neyKey under ZMK)] + 6-hex-digit KCV of new clear key.
func ExecuteA0(input []byte) ([]byte, error) {
	// Validate minimum input length: mode(1) + keytype(3) + scheme(1)
	if len(input) < 5 {
		return nil, errorcodes.Err15
	}

	mode := input[0]
	keyType := string(input[1:4])
	keyScheme := input[4]
	remainder := input[5:]

	logDebug(
		fmt.Sprintf(
			"A0 command input - mode: %c, key type: %s, scheme: %c",
			mode,
			keyType,
			keyScheme,
		),
	)

	// Validate mode (0=under LMK only, 1=under ZMK/TMK)
	if mode != '0' && mode != '1' {
		return nil, errorcodes.ErrA8
	}

	// Validate key scheme
	if keyScheme != 'U' && keyScheme != 'T' {
		return nil, errorcodes.Err26
	}

	keyLength := getKeyLength(keyScheme)
	logDebug(fmt.Sprintf("A0 generating random key of length: %d", keyLength))

	// Generate random key with proper length
	clearKey, err := randomKey(keyLength)
	if err != nil {
		return nil, errors.Join(errors.New("generate random key"), err)
	}

	logDebug(fmt.Sprintf("A0 generated clear key (hex): %s", cryptoutils.Raw2Str(clearKey)))

	// Calculate KCV using hex-encoded key
	kcv, err := cryptoutils.KeyCV([]byte(cryptoutils.Raw2Str(clearKey)), 6)
	if err != nil {
		return nil, errors.Join(errors.New("failed calculate kcv"), err)
	}

	logDebug(fmt.Sprintf("A0 calculated KCV: %s", string(kcv)))

	// Encrypt key under LMK
	lmkEncryptedKey, err := encryptUnderLMK(clearKey, keyType, keyScheme)
	if err != nil {
		return nil, errors.Join(errors.New("encrypt under lmk"), err)
	}

	logDebug(
		fmt.Sprintf("A0 key encrypted under LMK (hex): %s", cryptoutils.Raw2Str(lmkEncryptedKey)),
	)

	// Build response
	resp := []byte("A100")
	resp = appendEncryptedKeyToResponse(resp, keyScheme, lmkEncryptedKey)

	// Handle mode 1 - encrypt under ZMK/TMK if provided
	if mode == '1' {
		logDebug("A0 processing ZMK encryption mode")

		idx := 0
		if idx < len(remainder) && remainder[idx] == ';' {
			idx++
		}
		if idx >= len(remainder) {
			return nil, errorcodes.Err15
		}

		zmkScheme := remainder[idx]
		if zmkScheme != 'U' && zmkScheme != 'T' {
			return nil, errorcodes.Err05
		}
		idx++

		hexLen := getKeyLength(zmkScheme) * 2 // Convert bytes to hex chars
		if len(remainder) < idx+hexLen {
			return nil, errorcodes.Err15
		}

		hexZmk := remainder[idx : idx+hexLen]
		logDebug(fmt.Sprintf("A0 processing ZMK (hex): %s", string(hexZmk)))

		zmkBytes, err := hex.DecodeString(string(hexZmk))
		if err != nil {
			return nil, errors.Join(errors.New("zmk to binary"), err)
		}

		zmkEncryptedKey, err := encryptKeyUnderZMK(clearKey, zmkBytes)
		if err != nil {
			return nil, err
		}

		logDebug(
			fmt.Sprintf(
				"A0 key encrypted under ZMK (hex): %s",
				cryptoutils.Raw2Str(zmkEncryptedKey),
			),
		)

		resp = appendEncryptedKeyToResponse(resp, keyScheme, zmkEncryptedKey)
	}

	// Append KCV
	resp = append(resp, kcv...)

	logDebug(fmt.Sprintf("A0 final response: %s", string(resp)))

	return resp, nil
}
