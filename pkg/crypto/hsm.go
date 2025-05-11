package crypto

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
)

// Constants for key handling.
const (
	// Supported DES key lengths in bits.
	KeyLength64  = 64  // Single length DES key (8 bytes)
	KeyLength128 = 128 // Double length DES key (16 bytes)
	KeyLength192 = 192 // Triple length DES key (24 bytes)

	// Number of bytes in key check value.
	KCVLength = 3
)

// Common errors.
var (
	ErrInvalidKeyLength      = errors.New("invalid key length")
	ErrInvalidHexString      = errors.New("invalid hex string")
	ErrInvalidKeyFormat      = errors.New("invalid key format")
	ErrInvalidComponentCount = errors.New("invalid component count")
)

// GenerateKey generates a random cryptographic key of the specified length in bits.
// Returns the key as a hex string and its KCV, or an error if the length is invalid.
func GenerateKey(lengthBits int) (string, string, error) {
	// Validate key length
	if lengthBits != KeyLength64 &&
		lengthBits != KeyLength128 &&
		lengthBits != KeyLength192 {
		return "", "", ErrInvalidKeyLength
	}

	// Convert bits to bytes
	lengthBytes := lengthBits / 8
	keyBytes := make([]byte, lengthBytes)

	// Generate random key material
	if _, err := rand.Read(keyBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate random key: %w", err)
	}

	// Calculate KCV
	kcv := CalculateKCV(keyBytes)

	// Convert to hex strings
	keyHex := hex.EncodeToString(keyBytes)
	kcvHex := hex.EncodeToString(kcv)

	// Clean up key material from memory
	defer cleanBytes(keyBytes)

	return keyHex, kcvHex, nil
}

// SplitKey splits a key into the specified number of XOR components.
// The key must be provided as a hex string.
// Returns the components as hex strings and the KCV of the original key.
func SplitKey(keyHex string, numComponents int) ([]string, string, error) {
	// Validate number of components
	if numComponents < 2 {
		return nil, "", ErrInvalidComponentCount
	}

	// Validate hex string format
	if err := validateHexString(keyHex, 0); err != nil {
		return nil, "", err
	}

	// Decode key hex string
	keyBytes, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, "", ErrInvalidHexString
	}
	defer cleanBytes(keyBytes)

	// Create components
	componentLists := make([][]byte, numComponents)
	for i := 0; i < numComponents; i++ {
		componentLists[i] = make([]byte, len(keyBytes))
	}

	// Generate random components
	for i := 0; i < numComponents-1; i++ {
		if _, err := rand.Read(componentLists[i]); err != nil {
			cleanComponentLists(componentLists)
			return nil, "", fmt.Errorf("failed to generate component: %w", err)
		}
	}

	// Calculate final component using XOR
	copy(componentLists[numComponents-1], keyBytes)
	for i := 0; i < numComponents-1; i++ {
		xorBytes(componentLists[numComponents-1], componentLists[i])
	}

	// Calculate KCV of original key
	kcv := CalculateKCV(keyBytes)

	// Convert components to hex
	components := make([]string, numComponents)
	for i := 0; i < numComponents; i++ {
		components[i] = hex.EncodeToString(componentLists[i])
	}

	cleanComponentLists(componentLists)

	return components, hex.EncodeToString(kcv), nil
}

// CombineComponents combines multiple key components to reconstruct the original key.
// Components must be provided as hex strings.
// Returns the reconstructed key as a hex string.
func CombineComponents(components []string) (string, error) {
	// Validate input
	if len(components) < 2 {
		return "", ErrInvalidComponentCount
	}

	// Validate format of all components
	for _, comp := range components {
		if err := validateHexString(comp, 0); err != nil {
			return "", err
		}
	}

	// Decode first component to get length
	firstComponent, err := hex.DecodeString(components[0])
	if err != nil {
		return "", ErrInvalidHexString
	}
	defer cleanBytes(firstComponent)

	keyLength := len(firstComponent)
	resultBytes := make([]byte, keyLength)
	copy(resultBytes, firstComponent)

	// Combine remaining components using XOR
	for i := 1; i < len(components); i++ {
		componentBytes, err := hex.DecodeString(components[i])
		if err != nil {
			cleanBytes(resultBytes)
			return "", ErrInvalidHexString
		}
		if len(componentBytes) != keyLength {
			cleanBytes(resultBytes)
			cleanBytes(componentBytes)
			return "", ErrInvalidKeyLength
		}

		xorBytes(resultBytes, componentBytes)
		cleanBytes(componentBytes)
	}

	// Convert result to hex string
	resultHex := hex.EncodeToString(resultBytes)
	cleanBytes(resultBytes)

	return resultHex, nil
}

// CalculateKCV calculates a 3-byte Key Check Value for a key using DES.
// For single length key (8 bytes) - uses single DES.
// For double length key (16 bytes) - uses triple DES (EDE) with K1,K2,K1.
// For triple length key (24 bytes) - uses triple DES (EDE).
// If DES encryption fails, it falls back to using the first 3 bytes of the key.
func CalculateKCV(keyBytes []byte) []byte {
	if len(keyBytes) == 0 {
		// Return empty KCV for empty key
		return make([]byte, KCVLength)
	}

	var block cipher.Block
	var err error

	// Create appropriate cipher based on key length
	switch len(keyBytes) {
	case 8: // Single DES
		block, err = des.NewCipher(keyBytes)
	case 16: // Double DES (use as Triple DES with K1,K2,K1)
		// For double length key, use K1,K2,K1 mode
		tripleKey := make([]byte, 24)
		copy(tripleKey[:16], keyBytes)     // Copy K1,K2
		copy(tripleKey[16:], keyBytes[:8]) // Copy K1 again
		block, err = des.NewTripleDESCipher(tripleKey)
		defer cleanBytes(tripleKey)
	case 24: // Triple DES
		block, err = des.NewTripleDESCipher(keyBytes)
	default:
		// Invalid key length - fall back to first 3 bytes
		kcv := make([]byte, KCVLength)
		if len(keyBytes) >= KCVLength {
			copy(kcv, keyBytes[:KCVLength])
		} else {
			copy(kcv, keyBytes)
		}

		return kcv
	}

	if err != nil {
		// DES failed (e.g. weak key) - fall back to first 3 bytes
		kcv := make([]byte, KCVLength)
		if len(keyBytes) >= KCVLength {
			copy(kcv, keyBytes[:KCVLength])
		} else {
			copy(kcv, keyBytes)
		}

		return kcv
	}

	// Input block of all zeros
	input := make([]byte, 8)
	output := make([]byte, 8)
	defer cleanBytes(output)

	// Encrypt the zero block
	block.Encrypt(output, input)

	// Take first 3 bytes as KCV
	kcv := make([]byte, KCVLength)
	copy(kcv, output[:KCVLength])

	return kcv
}

// validateHexString checks if a string is a valid hex string
// that represents a byte array of a specific length (or any length if lengthBytes is 0).
func validateHexString(hexStr string, lengthBytes int) error {
	if len(hexStr)%2 != 0 {
		return ErrInvalidHexString
	}

	if lengthBytes > 0 && len(hexStr)/2 != lengthBytes {
		return ErrInvalidKeyLength
	}

	_, err := hex.DecodeString(hexStr)
	if err != nil {
		return ErrInvalidHexString
	}

	return nil
}

// Helper functions.

// xorBytes performs in-place XOR of two byte slices: dst ^= src.
func xorBytes(dst, src []byte) {
	for i := 0; i < len(dst); i++ {
		dst[i] ^= src[i]
	}
}

// cleanBytes overwrites a byte slice with zeros.
func cleanBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// cleanComponentLists cleans up component byte slices.
func cleanComponentLists(components [][]byte) {
	for i := range components {
		cleanBytes(components[i])
	}
}
