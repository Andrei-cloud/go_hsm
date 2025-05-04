// Package logic provides business logic for HSM commands.
package logic

import (
	"errors"
	"fmt"

	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteNC processes the NC payload and returns response bytes.
func ExecuteNC(input []byte,
	_ func([]byte) ([]byte, error),
	encryptUnderLMK func([]byte) ([]byte, error),
	logFn func(string),
) ([]byte, error) {
	logFn(fmt.Sprintf("NC command input length: %d", len(input)))

	if len(input) < 9 {
		return nil, errors.New("input too short")
	}

	logFn("NC calculating KCV using zero block.")

	// Use actual zero bytes for KCV calculation
	zeros := make([]byte, 16)
	kcvRaw, err := encryptUnderLMK(zeros)
	if err != nil {
		return nil, errors.Join(errors.New("calculate kcv"), err)
	}

	logFn(fmt.Sprintf("NC calculated KCV (hex): %s", cryptoutils.Raw2Str(kcvRaw[:8])))
	logFn(fmt.Sprintf("NC firmware version: %s", string(input)))

	// Format response: ND00 + KCV (16 chars) + firmware version from input
	resp := make([]byte, 0, 4+16+len(input))
	resp = append(resp, "ND00"...)                        // Command + status
	resp = append(resp, cryptoutils.Raw2B(kcvRaw[:8])...) // First 8 bytes of KCV in hex
	resp = append(resp, input...)                         // Firmware version from input parameter

	logFn(fmt.Sprintf("NC final response: %s", string(resp)))

	return resp, nil
}
