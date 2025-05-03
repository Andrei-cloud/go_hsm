// Package hsm provides the HSM service implementation and key management.
package hsm

import (
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"errors"
)

// HSM represents the hardware security module server holding the LMK, firmware version, and cipher for encryption operations.
type HSM struct {
	LMK             []byte
	FirmwareVersion string
	cipher          cipher.Block
}

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
