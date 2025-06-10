// Package keyblocklmk provides Thales/TR-31 key block wrapping under a default AES LMK.
package keyblocklmk

import (
	"crypto/aes"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	defaultAESLMKHex = "9B71333A13F9FAE72F9D0E2DAB4AD6784718012F9244033F3F26A2DE0C8AA11A"
)

var DefaultTestAESLMK []byte

func init() {
	var err error
	DefaultTestAESLMK, err = hex.DecodeString(defaultAESLMKHex)
	if err != nil {
		panic(fmt.Errorf("invalid default aes lmk hex: %w", err))
	}
}

// ComputeCheckValue computes the 3-byte Thales check value for an AES key.
// It encrypts an all-zero block under AES-ECB and returns the first 3 bytes as uppercase hex.
func ComputeCheckValue(key []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("aes cipher init failed: %w", err)
	}

	zeros := make([]byte, aes.BlockSize)
	encrypted := make([]byte, aes.BlockSize)
	block.Encrypt(encrypted, zeros)

	val := hex.EncodeToString(encrypted[:3])

	return strings.ToUpper(val), nil
}
