package keyblocklmk

import (
	"crypto/aes"
	"fmt"
)

// CalculateCMACCheckValue computes the AES key check value by calculating the AES-CMAC
// of a block of binary zeros using the provided AES key.
// It returns the first 8 bytes of the CMAC result as the check value.
func CalculateCMACCheckValue(aesKey []byte) ([]byte, error) {
	// computeAESCMAC will internally call aes.NewCipher, which validates key length.
	// So, no explicit key length check is needed here, but we must handle the error from it.

	zeroBlock := make([]byte, aes.BlockSize) // A block of binary zeros.

	cmac, err := computeAESCMAC(aesKey, zeroBlock)
	if err != nil {
		// Error from computeAESCMAC could be due to invalid key or other issues.

		return nil, fmt.Errorf("failed to compute CMAC for check value: %w", err)
	}

	// The check value is typically a portion of the CMAC.
	// Using the first 8 bytes as is a common practice for such check values.
	const checkValueLength = 8
	if len(cmac) < checkValueLength {
		// This should not happen if computeAESCMAC returns a full AES block size CMAC (16 bytes).

		return nil, fmt.Errorf("computed CMAC is too short (expected at least %d bytes, got %d)",
			checkValueLength, len(cmac))
	}

	checkValue := cmac[:checkValueLength]

	return checkValue, nil
}
