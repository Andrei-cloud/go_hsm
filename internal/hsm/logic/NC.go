// Package logic provides business logic for HSM commands.
package logic

import (
	"errors"

	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteNC processes the NC payload and returns response bytes.
func ExecuteNC(input []byte) ([]byte, error) {
	if len(input) < 48 {
		return nil, errors.New("input too short")
	}

	lmkHex := input[:48]
	firmware := input[48:]

	kcv, err := cryptoutils.KeyCV(lmkHex, 16)
	if err != nil {
		return nil, errors.Join(errors.New("calculate kcv"), err)
	}

	resp := make([]byte, 0, 4+len(kcv)+len(firmware))
	resp = append(resp, []byte("ND00")...)
	resp = append(resp, kcv...)
	resp = append(resp, firmware...)

	return resp, nil
}
