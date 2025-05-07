// Package cli contains utilities for CLI operations.
package cli

import (
	"errors"
	"fmt"

	"github.com/andrei-cloud/go_hsm/pkg/pinblock"
)

// GeneratePinBlock generates a PIN block using the provided PIN, PAN, and format code.
func GeneratePinBlock(pin, pan, formatCode string) (string, error) {
	if len(pin) < 4 || len(pin) > 12 {
		return "", errors.New("pin must be between 4 and 12 digits")
	}

	if len(pan) < 13 || len(pan) > 19 {
		return "", errors.New("pan must be between 13 and 19 digits")
	}

	generator := pinblock.GetGenerator(formatCode)
	if generator == nil {
		return "", fmt.Errorf("unsupported format code: %s", formatCode)
	}

	return generator.Encode(pin, pan)
}
