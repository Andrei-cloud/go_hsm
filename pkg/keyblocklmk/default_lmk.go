// Package keyblocklmk provides Thales key block wrapping under a default AES LMK.
package keyblocklmk

import (
	"encoding/hex"
	"fmt"
)

const (
	defaultAESLMKHex = "9B71333A13F9FAE72F9D0E2DAB4AD6784718012F9244033F3F26A2DE0C8AA11A"
)

var DefaultTestAESLMK []byte

func init() {
	var err error
	DefaultTestAESLMK, err = hex.DecodeString(defaultAESLMKHex)
	if err != nil {
		panic(fmt.Errorf("invalid default aes lmk hex: %w", err))
	}
}
