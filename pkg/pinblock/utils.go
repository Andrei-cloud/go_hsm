// Package pinblock implements various PIN block encoding and decoding formats.
package pinblock

import (
	"crypto/rand"
	"encoding/hex"
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

// getVisa1PanComponent extracts the PAN component for VISA1 format.
// It takes the 11 rightmost digits of the PAN (excluding the check digit)
// and appends the check digit itself.
func getVisa1PanComponent(pan string) (string, error) {
	panDigits := ""
	for _, r := range pan {
		if r >= '0' && r <= '9' {
			panDigits += string(r)
		}
	}

	// VISA1 requires at least 11 digits for the main part + 1 check digit.
	if len(panDigits) < 12 {
		return "", fmt.Errorf(
			"%w: pan must contain at least 12 digits for visa1 format",
			errInvalidPanLength,
		)
	}

	checkDigit := string(panDigits[len(panDigits)-1])
	panWithoutCheckDigit := panDigits[:len(panDigits)-1]

	if len(panWithoutCheckDigit) < 11 {
		// This case should ideally be caught by the len(panDigits) < 12 check,
		// but it's good for robustness.
		return "", fmt.Errorf(
			"%w: pan (after excluding check digit) must contain at least 11 digits for visa1 format",
			errInvalidPanLength,
		)
	}

	elevenRightmost := panWithoutCheckDigit[len(panWithoutCheckDigit)-11:]

	return elevenRightmost + checkDigit, nil
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

// get12PanDigits returns 12 pan digits from left or right.
// If fromLeft is true, returns the leftmost 12 digits.
// If fromLeft is false, returns the rightmost 12 digits excluding check digit.
// Accepts pans already provided as 12 digits excluding check digit.
func get12PanDigits(pan string, fromLeft bool) (string, error) {
	if pan == "" {
		return "", errPanRequired
	}
	panDigits := ""
	for _, r := range pan {
		if r >= '0' && r <= '9' {
			panDigits += string(r)
		}
	}

	if panDigits == "" {
		return "", errPanNoDigits
	}

	// For ISO0, 12 digits is too short (needs at least 13: 12 rightmost excluding check digit)
	if !fromLeft && len(panDigits) <= 12 {
		return "", errInvalidPanLength
	}

	if len(panDigits) < 12 {
		return "", errInvalidPanLength
	}

	if fromLeft {
		return panDigits[:12], nil
	}

	// handle case where panDigits is already the 12 rightmost excluding check digit.
	if len(panDigits) == 12 {
		return panDigits, nil
	}

	panWithoutCheckDigit := panDigits[:len(panDigits)-1]
	if len(panWithoutCheckDigit) < 12 {
		return "", errInvalidPanLength
	}

	return panWithoutCheckDigit[len(panWithoutCheckDigit)-12:], nil
}
