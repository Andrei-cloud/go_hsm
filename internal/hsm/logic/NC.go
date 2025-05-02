// Package logic provides business logic for HSM commands.
package logic

import (
	"errors"

	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
	"github.com/rs/zerolog/log"
)

// ExecuteNC processes the NC payload and returns response bytes.
func ExecuteNC(input []byte,
	_ func([]byte) ([]byte, error),
	encryptUnderLMK func([]byte) ([]byte, error),
) ([]byte, error) {
	log.Debug().
		Str("event", "nc_input_received").
		Str("input_hex", cryptoutils.Raw2Str(input)).
		Int("input_length", len(input)).
		Msg("received NC command input")

	if len(input) < 2 {
		return nil, errors.New("input too short")
	}

	// Use actual zero bytes for KCV calculation
	zeros := make([]byte, 16)
	kcvRaw, err := encryptUnderLMK(zeros)
	if err != nil {
		return nil, errors.Join(errors.New("calculate kcv"), err)
	}

	log.Debug().
		Str("event", "nc_kcv_calc").
		Str("zeros_hex", cryptoutils.Raw2Str(zeros)).
		Str("kcv_raw_hex", cryptoutils.Raw2Str(kcvRaw)).
		Msg("KCV calculation")

	// Format response: ND00 + KCV (16 chars) + firmware version from input
	resp := make([]byte, 0, 4+16+len(input))
	resp = append(resp, "ND00"...)                        // Command + status
	resp = append(resp, cryptoutils.Raw2B(kcvRaw[:8])...) // First 8 bytes of KCV in hex
	resp = append(resp, input...)                         // Firmware version from input parameter

	log.Debug().
		Str("event", "nc_format_response").
		Str("status", "ND00").
		Str("kcv_hex", cryptoutils.Raw2Str(kcvRaw[:8])).
		Str("firmware", string(input)).
		Str("response_hex", cryptoutils.Raw2Str(resp)).
		Int("response_len", len(resp)).
		Msg("formatted response")

	return resp, nil
}
