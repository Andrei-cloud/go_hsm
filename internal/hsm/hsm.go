// Package hsm provides the HSM service implementation and key management.
package hsm

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/andrei-cloud/go_hsm/pkg/pinblock"
)

// HSM represents the hardware security module server holding the LMK, firmware version, and cipher for encryption operations.
type HSM struct {
	LMK             []byte
	FirmwareVersion string
	cipher          cipher.Block
}

var errUnknownThalesPinBlockFormat = errors.New("unknown thales pin block format code")

// NewHSM creates a new HSM instance with the given LMK key in hex and firmware version.
// keyHex must be 16, 32, or 48 hex characters; shorter lengths are expanded automatically.
func NewHSM(keyHex, firmwareVersion string) (*HSM, error) {
	if len(keyHex)%16 != 0 || len(keyHex) > 48 {
		return nil, errors.New("invalid key hex length: must be 16, 32 or 48 hex characters")
	}
	switch len(keyHex) {
	case 16:
		keyHex = keyHex + keyHex + keyHex
	case 32:
		keyHex = keyHex + keyHex[:16]
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, err
	}
	cipherBlock, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}

	return &HSM{LMK: key, FirmwareVersion: firmwareVersion, cipher: cipherBlock}, nil
}

// EncryptUnderLMK encrypts the provided key under the LMK and returns the ciphertext.
func (h *HSM) EncryptUnderLMK(key []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 {
		return nil, errors.New("key length must be 16 or 24 bytes")
	}

	ciphertext := make([]byte, len(key))
	h.cipher.Encrypt(ciphertext[:8], key[:8])
	h.cipher.Encrypt(ciphertext[8:16], key[8:16])
	if len(key) == 24 {
		h.cipher.Encrypt(ciphertext[16:], key[16:])
	}

	return ciphertext, nil
}

// DecryptUnderLMK decrypts the provided key under the LMK and returns the plaintext.
func (h *HSM) DecryptUnderLMK(key []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 {
		return nil, errors.New("key length must be 16 or 24 bytes")
	}

	plaintext := make([]byte, len(key))
	h.cipher.Decrypt(plaintext[:8], key[:8])
	h.cipher.Decrypt(plaintext[8:16], key[8:16])
	if len(key) == 24 {
		h.cipher.Decrypt(plaintext[16:], key[16:])
	}

	return plaintext, nil
}

// GetPinBlockFormatFromThalesCode maps a Thales PIN block format code string
// to the corresponding pinblock.PinBlockFormat.
// The Thales codes are based on common interpretations of their documentation.
func GetPinBlockFormatFromThalesCode(thalesCode string) (pinblock.PinBlockFormat, error) {
	switch thalesCode {
	case "01": // Typically ISO 9564-1 Format 0.
		return pinblock.ISO0, nil
	case "02": // Docutel.
		return pinblock.DOCUTEL, nil
	case "03": // Diebold / IBM 3624.
		return pinblock.DIEBOLD, nil
	case "04": // PLUS Network.
		return pinblock.PLUSNETWORK, nil
	case "05": // Typically ISO 9564-1 Format 1.
		return pinblock.ISO1, nil
	case "34": // Typically ISO 9564-1 Format 2. (Decimal 34 from prompt).
		return pinblock.ISO2, nil
	case "35": // Mastercard Pay Now & Pay Later. (Decimal 35 from prompt).
		return pinblock.MASTERCARDPAYNOWPAYLATER, nil
	case "41": // Visa PIN-only change. (Decimal 41 from prompt).
		return pinblock.VISANEWPINONLY, nil
	case "42": // Visa old+new PIN change. (Decimal 42 from prompt).
		return pinblock.VISANEWOLDIN, nil
	case "47": // Typically ISO 9564-1 Format 3. (Decimal 47 from prompt).
		return pinblock.ISO3, nil
	case "48": // Typically ISO 9564-1 Format 4. (Decimal 48 from prompt).
		return pinblock.ISO4, nil
	default:
		// Return zero value for format and an error.
		return 0, fmt.Errorf("%w: %s", errUnknownThalesPinBlockFormat, thalesCode)
	}
}
