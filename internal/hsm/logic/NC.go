// Package logic provides business logic for HSM commands.
package logic

import (
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteNC processes the NC payload and returns response bytes.
func ExecuteNC(input []byte) ([]byte, error) {
	logDebug(fmt.Sprintf("NC command input length: %d", len(input)))

	if len(input) < 9 {
		return nil, errorcodes.Err15
	}

	logDebug("NC calculating KCV using zero block.")

	// Use actual zero bytes for KCV calculation.
	zeros := make([]byte, 16)
	kcvRaw, err := encryptUnderLMK(zeros)
	if err != nil {
		return nil, errorcodes.Err68
	}

	logDebug(fmt.Sprintf("NC calculated KCV (hex): %s", cryptoutils.Raw2Str(kcvRaw[:8])))
	logDebug(fmt.Sprintf("NC firmware version: %s", string(input)))

	// Format response: ND00 + KCV (16 chars) + firmware version from input.
	resp := make([]byte, 0, 4+16+len(input))
	resp = append(resp, "ND00"...)
	resp = append(resp, cryptoutils.Raw2B(kcvRaw[:8])...)
	resp = append(resp, input...)

	logDebug(fmt.Sprintf("NC final response: %s", string(resp)))

	return resp, nil
}
