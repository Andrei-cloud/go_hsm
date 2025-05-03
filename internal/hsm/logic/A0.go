// Package logic provides business logic for HSM commands.
package logic

import (
	"crypto/des"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
	"github.com/rs/zerolog/log"
)

// ExecuteA0 processes the A0 payload and returns response bytes.
// It always returns: "A1" + "00" + U|hex(newkey under lmk) [+ U|hex(neyKey under ZMK)] + 6-hex-digit KCV of new clear key.
func ExecuteA0(
	input []byte,
	decryptUnderLMK func([]byte) ([]byte, error),
	encryptUnderLMK func([]byte) ([]byte, error),
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
		log.Debug().
			Str("event", "a0_validation_error").
			Str("mode", string(mode)).
			Msg("invalid mode")

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

	// Generate random key
	clearKey := make([]byte, keyLength)
	if n, err := rand.Read(clearKey); err != nil {
		return nil, fmt.Errorf("generate random key: %w", err)
	} else if n != keyLength {
		return nil, errors.New("random read incomplete")
	}

	// Fix key parity using cryptoutils
	if !cryptoutils.CheckKeyParity(clearKey) {
		clearKey = cryptoutils.ModifyKeyParity(clearKey)
	}

	// Calculate KCV using cryptoutils
	kcv, err := cryptoutils.KeyCV(cryptoutils.Raw2B(clearKey), 6)
	if err != nil {
		return nil, fmt.Errorf("calculate kcv: %w", err)
	}

	// Handle mode 1 - encrypt under ZMK/TMK
	var zmkEncryptedKey []byte
	if mode == '1' {
		idx := 0
		// Optional delimiter
		if idx < len(remainder) && remainder[idx] == ';' {
			idx++
		}
		if idx >= len(remainder) {
			return nil, errorcodes.Err15
		}
		// ZMK/TMK scheme flag
		zmkScheme := remainder[idx]
		if zmkScheme != 'U' && zmkScheme != 'T' {
			return nil, errorcodes.Err05
		}
		idx++
		// Determine expected hex length
		hexLen := 32 // Double length
		if zmkScheme == 'T' {
			hexLen = 48 // Triple length
		}

		if len(remainder) < idx+hexLen {
			return nil, errorcodes.Err15
		}

		hexZmk := remainder[idx : idx+hexLen]
		// Decode and decrypt ZMK/TMK
		zmkBytes, err := cryptoutils.B2Raw(hexZmk)
		if err != nil {
			return nil, fmt.Errorf("decode zmk: %w", err)
		}

		rawZmk, err := decryptUnderLMK(zmkBytes)
		if err != nil {
			return nil, fmt.Errorf("decrypt zmk: %w", err)
		}

		// Verify ZMK parity using cryptoutils
		if !cryptoutils.CheckKeyParity(rawZmk) {
			return []byte("A1" + errorcodes.Err01.CodeOnly()), nil
		}

		// Create ZMK cipher
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
			return nil, fmt.Errorf("create zmk cipher: %w", err)
		}

		// Encrypt under ZMK
		zmkEncryptedKey = make([]byte, len(clearKey))
		for i := 0; i < len(clearKey); i += 8 {
			zmkBlock.Encrypt(zmkEncryptedKey[i:i+8], clearKey[i:i+8])
		}
	}

	// Encrypt key under LMK
	lmkEncryptedKey, err := encryptUnderLMK(clearKey)
	if err != nil {
		return nil, fmt.Errorf("encrypt under lmk: %w", err)
	}

	// Build response
	resp := []byte("A100")
	resp = append(resp, 'U')
	resp = append(resp, cryptoutils.Raw2B(lmkEncryptedKey)...)

	if zmkEncryptedKey != nil {
		resp = append(resp, 'U')
		resp = append(resp, cryptoutils.Raw2B(zmkEncryptedKey)...)
	}

	// Append KCV
	resp = append(resp, kcv...)

	return resp, nil
}
