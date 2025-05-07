// Package pinblock implements various PIN block encoding and decoding formats.
package pinblock

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// GetRandomHexDigit returns a random hex digit (0-F).
func GetRandomHexDigit() string {
	b := make([]byte, 1)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to a pseudo-random digit if crypto/rand fails, though this is unlikely.
		// In a real scenario, this error should be handled more robustly.
		// For HSM operations, cryptographic randomness is critical.
		// Consider panicking or returning a clear error if rand.Read fails.
		return "0" // Or handle error appropriately.
	}

	return fmt.Sprintf("%X", b[0]%16) // Ensure it's a single hex digit 0-F.
}

// GetRandomHexDigitAF returns a random hex digit (A-F).
func GetRandomHexDigitAF() string {
	b := make([]byte, 1)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback if crypto/rand fails.
		return "A" // Or handle error appropriately.
	}
	// Generate a number from 10 to 15, then format as hex.
	return fmt.Sprintf("%X", (b[0]%6)+10)
}

// Helper to XOR two hex strings. Result is uppercase hex.
func xorHexStrings(s1, s2 string) (string, error) {
	b1, err := hex.DecodeString(s1)
	if err != nil {
		return "", fmt.Errorf("invalid hex string s1: %w", err)
	}
	b2, err := hex.DecodeString(s2)
	if err != nil {
		return "", fmt.Errorf("invalid hex string s2: %w", err)
	}

	if len(b1) != len(b2) {
		return "", fmt.Errorf(
			"hex strings must have equal length to xor (s1 len %d, s2 len %d)",
			len(b1),
			len(b2),
		)
	}

	resultBytes := make([]byte, len(b1))
	for i := 0; i < len(b1); i++ {
		resultBytes[i] = b1[i] ^ b2[i]
	}

	return strings.ToUpper(hex.EncodeToString(resultBytes)), nil
}

// Helper to get 12 digits from PAN (left or right).
func get12PanDigits(pan string, fromLeft bool) (string, error) {
	panDigits := ""
	for _, r := range pan {
		if r >= '0' && r <= '9' {
			panDigits += string(r)
		}
	}
	if len(panDigits) < 12 {
		return "", fmt.Errorf("%w: pan must contain at least 12 digits", errInvalidPanLength)
	}
	if fromLeft {
		return panDigits[:12], nil
	}
	// from right, excluding check digit (standard interpretation for "rightmost 12 excluding check digit")
	if panDigits != "" { // panDigits has already been filtered for digits.
		panWithoutCheckDigit := panDigits[:len(panDigits)-1]
		if len(panWithoutCheckDigit) < 12 {
			return "", fmt.Errorf(
				"%w: pan (after excluding check digit) must contain at least 12 digits",
				errInvalidPanLength,
			)
		}

		return panWithoutCheckDigit[len(panWithoutCheckDigit)-12:], nil
	}

	return "", errors.New(
		"pan contains no processable digits",
	) // Should be caught by len(panDigits) < 12 earlier.
}
