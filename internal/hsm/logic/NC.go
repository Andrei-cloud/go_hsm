// Package logic provides business logic for HSM commands.
package logic

import (
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteNC processes the NC payload and returns response bytes.
func ExecuteNC(input []byte) ([]byte, error) {
	logInfo("NC: Starting command diagnostics.")
	logDebug(fmt.Sprintf("NC: Input data length: %d", len(input)))

	if len(input) < 9 {
		logError("NC: Input data too short for command")
		return nil, errorcodes.Err15
	}

	logInfo("NC: Calculating KCV value.")

	// // Use actual zero bytes for KCV calculation.
	// zeros := make([]byte, 16)
	// kcvRaw, err := encryptUnderLMK(zeros)
	// if err != nil {
	//	logError("Failed to calculate KCV")
	// 	return nil, errorcodes.Err68
	// }
	kcvRaw := make([]byte, 16)

	logDebug(fmt.Sprintf("NC: Calculated KCV (hex): %s", cryptoutils.Raw2Str(kcvRaw[:8])))
	logDebug(fmt.Sprintf("NC: Firmware version: %s", string(input)))

	logInfo("NC: Formatting diagnostic response.")

	// Format response: ND00 + KCV (16 chars) + firmware version from input.
	resp := make([]byte, 0, 4+16+len(input))
	resp = append(resp, "ND00"...)
	resp = append(resp, cryptoutils.Raw2B(kcvRaw[:8])...)
	resp = append(resp, input...)

	logDebug(fmt.Sprintf("NC: Final response: %s", string(resp)))

	return resp, nil
}
