// Package logic provides business logic for HSM commands.
package logic

import (
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
	"github.com/rs/zerolog/log"
)

// ExecuteA0 processes the A0 payload and returns response bytes.
// It always returns: "A1" + "00" + U|hex(clearKey) [+ U|hex(clearKey under ZMK)] + 6-hex-digit KCV.
func ExecuteA0(
	input []byte,
	decryptUnderLMK func([]byte) ([]byte, error),
	_ func([]byte) ([]byte, error),
) ([]byte, error) {
	if len(input) < 5 {
		log.Debug().
			Str("event", "a0_validation_error").
			Int("input_length", len(input)).
			Msg("input too short")

		return nil, errors.New("input too short")
	}

	mode := input[0]
	keyType := string(input[1:4])
	keyScheme := string(input[4:5])
	remainder := input[5:]

	log.Debug().
		Str("event", "a0_parse_input").
		Str("mode", string(mode)).
		Str("key_type", keyType).
		Str("key_scheme", keyScheme).
		Int("remainder_length", len(remainder)).
		Msg("parsed A0 command input")

	// ZMK field if mode=='1' and format is U|<32-hex-chars>
	var rawZmk []byte
	if mode == '1' && len(remainder) >= 1 && remainder[0] == 'U' {
		if len(remainder) < 33 {
			log.Debug().
				Str("event", "a0_zmk_error").
				Int("zmk_length", len(remainder)).
				Msg("zmk field too short")
			return nil, errors.New("zmk field too short")
		}
		zmkField := remainder[:33] // including the leading 'U'

		// decrypt ZMK under LMK
		hexZmk := zmkField[1:] // drop leading 'U'
		zmkBytes, err := cryptoutils.B2Raw(hexZmk)
		if err != nil {
			log.Debug().
				Str("event", "a0_zmk_decode_error").
				Err(err).
				Str("zmk_hex", string(hexZmk)).
				Msg("failed to decode zmk hex")

			return nil, fmt.Errorf("decode zmk: %w", err)
		}

		log.Debug().
			Str("event", "a0_decrypt_zmk").
			Str("zmk_hex", string(hexZmk)).
			Int("zmk_length", len(zmkBytes)).
			Msg("decrypting ZMK under LMK")

		rawZmk, err = decryptUnderLMK(zmkBytes)
		if err != nil {
			log.Debug().
				Str("event", "a0_zmk_decrypt_error").
				Err(err).
				Msg("failed to decrypt zmk under LMK")

			return nil, fmt.Errorf("decrypt zmk: %w", err)
		}

		log.Debug().
			Str("event", "a0_zmk_decrypted").
			Int("raw_zmk_length", len(rawZmk)).
			Str("raw_zmk_hex", hex.EncodeToString(rawZmk)).
			Msg("successfully decrypted ZMK")
	}

	// generate new 16-byte key
	clearKey := make([]byte, 16)
	if n, err := rand.Read(clearKey); err != nil {
		log.Debug().
			Str("event", "a0_key_gen_error").
			Err(err).
			Msg("failed to generate random key")

		return nil, fmt.Errorf("generate random key: %w", err)
	} else if n != len(clearKey) {
		log.Debug().
			Str("event", "a0_key_gen_error").
			Int("bytes_read", n).
			Int("expected_bytes", len(clearKey)).
			Msg("random read incomplete")

		return nil, errors.New("random read failed")
	}

	log.Debug().
		Str("event", "a0_key_generated").
		Int("key_length", len(clearKey)).
		Str("key_hex", hex.EncodeToString(clearKey)).
		Msg("generated new random key")

	// parity adjustment
	clearKey = cryptoutils.ModifyKeyParity(clearKey)

	log.Debug().
		Str("event", "a0_key_parity").
		Str("key_hex_after_parity", hex.EncodeToString(clearKey)).
		Msg("adjusted key parity")

	// start building response
	resp := []byte("A100")   // A1 + 00 (no error)
	resp = append(resp, 'U') // marker for hex under LMK
	resp = append(resp, cryptoutils.Raw2B(clearKey)...)

	// if there was a ZMK field, encrypt under ZMK and append
	if rawZmk != nil {
		// expand 16->24 or accept 24
		var fullZmk []byte
		switch len(rawZmk) {
		case 16:
			fullZmk = append(rawZmk, rawZmk[:8]...)
			log.Debug().
				Str("event", "a0_zmk_expand").
				Int("original_length", len(rawZmk)).
				Int("expanded_length", len(fullZmk)).
				Msg("expanded 16-byte ZMK to 24 bytes")
		case 24:
			fullZmk = rawZmk
			log.Debug().
				Str("event", "a0_zmk_use").
				Int("zmk_length", len(rawZmk)).
				Msg("using 24-byte ZMK as is")
		default:
			log.Debug().
				Str("event", "a0_zmk_length_error").
				Int("zmk_length", len(rawZmk)).
				Msg("invalid zmk length")

			return nil, errors.New("invalid zmk length")
		}

		block, err := des.NewTripleDESCipher(fullZmk)
		if err != nil {
			log.Debug().
				Str("event", "a0_zmk_cipher_error").
				Err(err).
				Msg("failed to create zmk cipher")

			return nil, fmt.Errorf("create zmk cipher: %w", err)
		}

		newUnderZmk := make([]byte, 16)
		block.Encrypt(newUnderZmk[:8], clearKey[:8])
		block.Encrypt(newUnderZmk[8:], clearKey[8:])

		log.Debug().
			Str("event", "a0_key_under_zmk").
			Str("key_under_zmk_hex", hex.EncodeToString(newUnderZmk)).
			Msg("encrypted key under ZMK")

		resp = append(resp, 'U')
		resp = append(resp, cryptoutils.Raw2B(newUnderZmk)...)
	}

	// always append 6-hex-digit KCV of the clear key (extended to 24 bytes if needed)
	var cvKey []byte
	switch len(clearKey) {
	case 16:
		cvKey = append(clearKey, clearKey[:8]...)
		log.Debug().
			Str("event", "a0_kcv_key_expand").
			Int("original_length", len(clearKey)).
			Int("expanded_length", len(cvKey)).
			Msg("expanded key for KCV calculation")
	case 24:
		cvKey = clearKey
	default:
		cvKey = clearKey
	}
	kcv, err := cryptoutils.KeyCV(cryptoutils.Raw2B(cvKey), 6)
	if err != nil {
		log.Debug().
			Str("event", "a0_kcv_error").
			Err(err).
			Msg("failed to calculate kcv")

		return nil, fmt.Errorf("calculate kcv: %w", err)
	}

	log.Debug().
		Str("event", "a0_kcv_calculated").
		Str("kcv_hex", string(kcv)).
		Msg("calculated key check value")

	resp = append(resp, kcv...)

	log.Debug().
		Str("event", "a0_response").
		Int("response_length", len(resp)).
		Str("response_hex", hex.EncodeToString(resp)).
		Msg("built final A0 response")

	return resp, nil
}
