// Package logic provides business logic for HSM commands.
package logic

import (
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
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
	log.Debug().
		Str("event", "a0_input").
		Str("input_hex", hex.EncodeToString(input)).
		Int("input_length", len(input)).
		Msg("processing A0 command")

	// Validate minimum input length: mode(1) + keytype(3) + scheme(1)
	if len(input) < 5 {
		log.Debug().
			Str("event", "a0_validation_error").
			Int("input_length", len(input)).
			Msg("input too short")

		return nil, errorcodes.Err15
	}

	mode := input[0]
	keyType := string(input[1:4])
	keyScheme := input[4]
	remainder := input[5:]

	log.Debug().
		Str("event", "a0_parse_input").
		Str("mode", string(mode)).
		Str("key_type", keyType).
		Str("key_scheme", string(keyScheme)).
		Int("remainder_length", len(remainder)).
		Msg("parsed A0 command input")

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
		log.Debug().
			Str("event", "a0_validation_error").
			Str("scheme", string(keyScheme)).
			Msg("invalid key scheme")

		return nil, errorcodes.Err26
	}

	// Determine key length based on scheme
	keyLength := 16 // 'U' scheme = double length
	if keyScheme == 'T' {
		keyLength = 24 // 'T' scheme = triple length
	}

	log.Debug().
		Str("event", "a0_key_length").
		Int("length", keyLength).
		Str("scheme", string(keyScheme)).
		Msg("determined key length")

	// Generate random key
	clearKey := make([]byte, keyLength)
	if n, err := rand.Read(clearKey); err != nil {
		log.Debug().
			Str("event", "a0_key_gen_error").
			Err(err).
			Msg("failed to generate random key")

		return nil, fmt.Errorf("generate random key: %w", err)
	} else if n != keyLength {
		log.Debug().
			Str("event", "a0_key_gen_error").
			Int("bytes_read", n).
			Int("expected_length", keyLength).
			Msg("random read incomplete")

		return nil, errors.New("random read incomplete")
	}

	log.Debug().
		Str("event", "a0_key_generated").
		Int("key_length", keyLength).
		Str("key_hex", hex.EncodeToString(clearKey)).
		Msg("generated new random key")

	// Fix key parity using cryptoutils
	originalParity := cryptoutils.CheckKeyParity(clearKey)
	clearKey = cryptoutils.ModifyKeyParity(clearKey)
	newParity := cryptoutils.CheckKeyParity(clearKey)

	log.Debug().
		Str("event", "a0_key_parity").
		Bool("original_parity_ok", originalParity).
		Bool("new_parity_ok", newParity).
		Str("key_hex", hex.EncodeToString(clearKey)).
		Msg("adjusted key parity")

	// Calculate KCV using cryptoutils
	kcv, err := cryptoutils.KeyCV(cryptoutils.Raw2B(clearKey), 6)
	if err != nil {
		log.Debug().
			Str("event", "a0_kcv_error").
			Err(err).
			Msg("failed to calculate KCV")

		return nil, fmt.Errorf("calculate kcv: %w", err)
	}

	log.Debug().
		Str("event", "a0_kcv_calculated").
		Str("kcv_hex", string(kcv)).
		Msg("calculated key check value")

	// Handle mode 1 - encrypt under ZMK/TMK
	var zmkEncryptedKey []byte
	if mode == '1' {
		idx := 0
		// Optional delimiter
		if idx < len(remainder) && remainder[idx] == ';' {
			idx++
		}
		if idx >= len(remainder) {
			log.Debug().
				Str("event", "a0_zmk_error").
				Msg("missing ZMK data")

			return nil, errorcodes.Err15
		}
		// ZMK/TMK scheme flag
		zmkScheme := remainder[idx]
		if zmkScheme != 'U' && zmkScheme != 'T' {
			log.Debug().
				Str("event", "a0_zmk_error").
				Str("scheme", string(zmkScheme)).
				Msg("invalid ZMK scheme")

			return nil, errorcodes.Err05
		}
		idx++
		// Determine expected hex length
		hexLen := 32 // Double length
		if zmkScheme == 'T' {
			hexLen = 48 // Triple length
		}

		log.Debug().
			Str("event", "a0_zmk_parse").
			Str("scheme", string(zmkScheme)).
			Int("hex_length", hexLen).
			Msg("parsing ZMK")

		if len(remainder) < idx+hexLen {
			log.Debug().
				Str("event", "a0_zmk_error").
				Int("remaining_length", len(remainder)-idx).
				Int("required_length", hexLen).
				Msg("ZMK data too short")

			return nil, errorcodes.Err15
		}

		hexZmk := remainder[idx : idx+hexLen]
		// Decode and decrypt ZMK/TMK
		zmkBytes, err := cryptoutils.B2Raw(hexZmk)
		if err != nil {
			log.Debug().
				Str("event", "a0_zmk_error").
				Err(err).
				Msg("failed to decode ZMK hex")

			return nil, fmt.Errorf("decode zmk: %w", err)
		}

		rawZmk, err := decryptUnderLMK(zmkBytes)
		if err != nil {
			log.Debug().
				Str("event", "a0_zmk_error").
				Err(err).
				Msg("failed to decrypt ZMK")

			return nil, fmt.Errorf("decrypt zmk: %w", err)
		}

		// Verify ZMK parity using cryptoutils
		if !cryptoutils.CheckKeyParity(rawZmk) {
			log.Debug().
				Str("event", "a0_zmk_error").
				Msg("ZMK parity check failed")

			return []byte("A1" + errorcodes.Err01.CodeOnly()), nil
		}

		log.Debug().
			Str("event", "a0_zmk_verified").
			Str("scheme", string(zmkScheme)).
			Int("zmk_length", len(rawZmk)).
			Msg("ZMK verified")

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
			log.Debug().
				Str("event", "a0_zmk_error").
				Err(err).
				Msg("failed to create ZMK cipher")

			return nil, fmt.Errorf("create zmk cipher: %w", err)
		}

		// Encrypt under ZMK
		zmkEncryptedKey = make([]byte, len(clearKey))
		for i := 0; i < len(clearKey); i += 8 {
			zmkBlock.Encrypt(zmkEncryptedKey[i:i+8], clearKey[i:i+8])
		}

		log.Debug().
			Str("event", "a0_zmk_encrypted").
			Str("encrypted_hex", hex.EncodeToString(zmkEncryptedKey)).
			Msg("encrypted key under ZMK")
	}

	// Encrypt key under LMK
	lmkEncryptedKey, err := encryptUnderLMK(clearKey)
	if err != nil {
		log.Debug().
			Str("event", "a0_lmk_encrypt_error").
			Err(err).
			Msg("failed to encrypt under LMK")

		return nil, fmt.Errorf("encrypt under lmk: %w", err)
	}

	log.Debug().
		Str("event", "a0_lmk_encrypted").
		Str("encrypted_hex", hex.EncodeToString(lmkEncryptedKey)).
		Msg("encrypted key under LMK")

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

	log.Debug().
		Str("event", "a0_response").
		Int("response_length", len(resp)).
		Str("response_hex", hex.EncodeToString(resp)).
		Bool("has_zmk", zmkEncryptedKey != nil).
		Msg("built final A0 response")

	return resp, nil
}
