//go:build !test

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
	logDebug(fmt.Sprintf("NC: Input data hex: %x", input))

	if len(input) < 9 {
		logError("NC: Input data too short for command")
		return nil, errorcodes.Err15
	}

	// Extract and validate firmware version
	version := string(input)
	logInfo("NC: Processing firmware version.")
	logDebug(fmt.Sprintf("NC: Firmware version: %s", version))

	logInfo("NC: Calculating KCV value.")
	// When LMK is available:
	// zeros := make([]byte, 16)
	// kcvRaw, err := LMKProviderInstance.EncryptUnderLMK(zeros)
	// if err != nil {
	//   logError("NC: Failed to calculate KCV")
	//   return nil, errorcodes.Err68
	// }

	// For now use dummy KCV
	kcvRaw := make([]byte, 16)
	logDebug(fmt.Sprintf("NC: Calculated KCV hex: %x", kcvRaw[:8]))

	// Format response: ND00 + KCV (16 chars) + firmware version
	logInfo("NC: Formatting diagnostic response.")
	resp := make([]byte, 0, 4+16+len(input))
	resp = append(resp, "ND00"...)
	resp = append(resp, cryptoutils.Raw2B(kcvRaw[:8])...)
	resp = append(resp, input...)

	logDebug(fmt.Sprintf("NC: Final response hex: %x", resp))

	return resp, nil
}
