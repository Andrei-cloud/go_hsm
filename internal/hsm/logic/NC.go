// Package logic provides business logic for HSM commands.
package logic

import (
	"errors"

	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteNC processes the NC payload and returns response bytes.
func ExecuteNC(input []byte,
	_ func([]byte) ([]byte, error),
	encryptUnderLMK func([]byte) ([]byte, error),
	logFn func(string),
) ([]byte, error) {
	if len(input) < 9 {
		return nil, errors.New("input too short")
	}

	// Use actual zero bytes for KCV calculation
	zeros := make([]byte, 16)
	kcvRaw, err := encryptUnderLMK(zeros)
	if err != nil {
		return nil, errors.Join(errors.New("calculate kcv"), err)
	}

	// Format response: ND00 + KCV (16 chars) + firmware version from input
	resp := make([]byte, 0, 4+16+len(input))
	resp = append(resp, "ND00"...)                        // Command + status
	resp = append(resp, cryptoutils.Raw2B(kcvRaw[:8])...) // First 8 bytes of KCV in hex
	resp = append(resp, input...)                         // Firmware version from input parameter

	return resp, nil
}
