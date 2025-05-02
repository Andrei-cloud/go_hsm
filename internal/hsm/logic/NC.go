// Package logic provides business logic for HSM commands.
package logic

import (
	"encoding/hex"
	"errors"

	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
	"github.com/rs/zerolog/log"
)

// ExecuteNC processes the NC payload and returns response bytes.
func ExecuteNC(input []byte,
	_ func([]byte) ([]byte, error),
	encryptUnderLMK func([]byte) ([]byte, error),
) ([]byte, error) {
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
		Str("zeros_hex", hex.EncodeToString(zeros)).
		Str("kcv_raw_hex", hex.EncodeToString(kcvRaw)).
		Msg("KCV calculation")

	// Format response: ND00 + KCV + firmware version.
	resp := make([]byte, 0, 4+16+len(input))              // ND00 + 16 hex KCV + firmware
	resp = append(resp, "ND00"...)                        // Status
	resp = append(resp, cryptoutils.Raw2B(kcvRaw[:8])...) // KCV
	// append firmware version constant
	resp = append(resp, input...)

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
