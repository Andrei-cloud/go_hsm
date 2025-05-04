// Package logic provides business logic for HSM commands.
package logic

import (
	"crypto/des"
	"errors"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteA0 processes the A0 payload and returns response bytes.
// It always returns: "A1" + "00" + U|hex(newkey under lmk) [+ U|hex(neyKey under ZMK)] + 6-hex-digit KCV of new clear key.
func ExecuteA0(
	input []byte,
	decryptUnderLMK func([]byte) ([]byte, error),
	encryptUnderLMK func([]byte) ([]byte, error),
	logFn func(string),
) ([]byte, error) {
	// Validate minimum input length: mode(1) + keytype(3) + scheme(1)
	if len(input) < 5 {
		return nil, errorcodes.Err15
	}

	mode := input[0]
	keyType := string(input[1:4])
	keyScheme := input[4]
	remainder := input[5:]

	_ = keyType // Unused in this implementation

	// Validate mode (0=under LMK only, 1=under ZMK/TMK)
	if mode != '0' && mode != '1' {
		return nil, errorcodes.ErrA8
	}

	// Validate key scheme
	if keyScheme != 'U' && keyScheme != 'T' {
		return nil, errorcodes.Err26
	}

	// Determine key length based on scheme
	keyLength := 16 // 'U' scheme = double length
	if keyScheme == 'T' {
		keyLength = 24 // 'T' scheme = triple length
	}

	// Generate random key with proper length
	clearKey, err := cryptoutils.GenerateRandomKey(keyLength)
	if err != nil {
		return nil, errors.Join(errors.New("generate random key"), err)
	}

	logFn("A0 clear key: " + cryptoutils.Raw2Str(clearKey))

	// Calculate KCV using hex-encoded key
	kcv, err := cryptoutils.KeyCV([]byte(cryptoutils.Raw2Str(clearKey)), 6)
	if err != nil {
		return nil, errors.Join(errors.New("failed calculate kcv"), err)
	}

	logFn("A0 kcv: " + string(kcv))

	// Encrypt key under LMK
	lmkEncryptedKey, err := encryptUnderLMK(clearKey)
	if err != nil {
		return nil, errors.Join(errors.New("encrypt under lmk"), err)
	}

	// Build response
	resp := []byte("A100")
	resp = append(resp, keyScheme)
	// Only use original key length bytes for hex encoding
	resp = append(resp, cryptoutils.Raw2B(lmkEncryptedKey[:keyLength])...)

	// Handle mode 1 - encrypt under ZMK/TMK if provided
	if mode == '1' {
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
		hexLen := 32 // Double length
		if zmkScheme == 'T' {
			hexLen = 48 // Triple length
		}
		if len(remainder) < idx+hexLen {
			return nil, errorcodes.Err15
		}

		hexZmk := remainder[idx : idx+hexLen]
		zmkBytes, err := cryptoutils.B2Raw(hexZmk)
		if err != nil {
			return nil, errors.Join(errors.New("zmk to binary"), err)
		}

		rawZmk, err := decryptUnderLMK(zmkBytes)
		if err != nil {
			return nil, errors.Join(errors.New("decrypt zmk"), err)
		}

		// Create ZMK cipher - use only actual key length for triple DES
		var fullZmk []byte
		if len(rawZmk) == 16 {
			fullZmk = make([]byte, 24)
			copy(fullZmk, rawZmk)
			copy(fullZmk[16:], rawZmk[:8])
		} else {
			fullZmk = rawZmk
		}

		zmkBlock, err := des.NewTripleDESCipher(fullZmk)
		if err != nil {
			return nil, errors.Join(errors.New("create zmk cipher"), err)
		}

		// Encrypt under ZMK
		zmkEncryptedKey := make([]byte, len(clearKey))
		for i := 0; i < len(clearKey); i += 8 {
			zmkBlock.Encrypt(zmkEncryptedKey[i:i+8], clearKey[i:i+8])
		}

		resp = append(resp, keyScheme)
		// Only use original key length bytes for hex encoding
		resp = append(resp, cryptoutils.Raw2B(zmkEncryptedKey[:keyLength])...)
	}

	// Append KCV
	resp = append(resp, kcv...)

	return resp, nil
}
