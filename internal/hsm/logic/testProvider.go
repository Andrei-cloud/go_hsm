package logic

import (
	"crypto/des"
	"encoding/hex"
	"errors"
	"fmt"
)

const testLMKKeyHex = "0123456789ABCDEFFEDCBA9876543210"

// SetupTestLMKProvider sets LMKProviderInstance to a deterministic test provider for unit tests.
// The test provider uses a fixed LMK key and deterministic random key generation.
func SetupTestLMKProvider() error {
	testKey, err := hex.DecodeString(testLMKKeyHex)
	if err != nil {
		return fmt.Errorf("invalid test key hex: %w", err)
	}

	if len(testKey) != 16 {
		return errors.New("test key must be 16 bytes (double-length DES key)")
	}

	LMKProviderInstance = LMKProvider{
		EncryptUnderLMK: func(plainKey []byte, _ string, _ byte) ([]byte, error) {
			return testEncryptWithLMK(plainKey, testKey)
		},
		DecryptUnderLMK: func(encryptedKey []byte, _ string, _ byte) ([]byte, error) {
			return testDecryptWithLMK(encryptedKey, testKey)
		},
		RandomKey: testRandomKey,
	}

	return nil
}

// testEncryptWithLMK encrypts data using the test LMK key.
func testEncryptWithLMK(plainKey, testKey []byte) ([]byte, error) {
	if len(plainKey) == 0 || len(plainKey)%8 != 0 {
		return nil, errors.New("invalid plaintext key length")
	}

	block, err := des.NewTripleDESCipher(prepareTripleDESKey(testKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	result := make([]byte, len(plainKey))
	for i := 0; i < len(plainKey); i += 8 {
		block.Encrypt(result[i:i+8], plainKey[i:i+8])
	}

	return result, nil
}

// testDecryptWithLMK decrypts data using the test LMK key.
func testDecryptWithLMK(encryptedKey, testKey []byte) ([]byte, error) {
	if len(encryptedKey) == 0 || len(encryptedKey)%8 != 0 {
		return nil, errors.New("invalid encrypted key length")
	}

	block, err := des.NewTripleDESCipher(prepareTripleDESKey(testKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	result := make([]byte, len(encryptedKey))
	for i := 0; i < len(encryptedKey); i += 8 {
		block.Decrypt(result[i:i+8], encryptedKey[i:i+8])
	}

	return result, nil
}

// testRandomKey generates deterministic pseudo-random keys for testing.
func testRandomKey(length int) ([]byte, error) {
	if length != 8 && length != 16 && length != 24 {
		return nil, errors.New("invalid key length")
	}

	result := make([]byte, length)
	for i := 0; i < length; i++ {
		result[i] = byte((i*7 + 0x42) % 256)
	}

	// Set odd parity for DES keys.
	for i := 0; i < length; i++ {
		b := result[i]
		bitCount := 0
		for j := 1; j < 8; j++ {
			if (b & (1 << j)) != 0 {
				bitCount++
			}
		}
		if bitCount%2 == 0 {
			result[i] |= 1
		} else {
			result[i] &= 0xFE
		}
	}

	return result, nil
}
