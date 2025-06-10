package keyblocklmk

import (
	"fmt"
)

// Header represents the 16-byte Key Block Header common to both Thales 'S' and TR-31 'R'.
type Header struct {
	Version        byte   // Key Block Version ID (e.g. 'D').
	KeyUsage       string // 2-byte usage code.
	Algorithm      byte   // Algorithm character.
	ModeOfUse      byte   // Mode of use.
	KeyVersionNum  string // 2-digit key version number.
	Exportability  byte   // Exportability.
	OptionalBlocks byte   // Number of optional header blocks (0–99).
	KeyContext     byte   // Key context or LMK variant ID.
}

// toBytes serializes the Header into its 16-byte representation.
func (h Header) toBytes() ([]byte, error) {
	if len(h.KeyUsage) != 2 || len(h.KeyVersionNum) != 2 {
		return nil, fmt.Errorf("KeyUsage and KeyVersionNum must be 2 characters each.")
	}
	b := make([]byte, 16)
	b[0] = h.Version
	copy(b[1:3], []byte(h.KeyUsage))
	b[3] = h.Algorithm
	b[4] = h.ModeOfUse
	copy(b[5:7], []byte(h.KeyVersionNum))
	b[7] = h.Exportability
	b[8] = '0' + (h.OptionalBlocks / 10)
	b[9] = '0' + (h.OptionalBlocks % 10)
	b[10] = h.KeyContext
	for i := 11; i < 16; i++ {
		b[i] = 0x00
	}
	return b, nil
}

// fromBytes parses a 16-byte slice into a Header.
func (h *Header) fromBytes(data []byte) error {
	if len(data) != 16 {
		return fmt.Errorf("header must be 16 bytes, got %d.", len(data))
	}
	h.Version = data[0]
	h.KeyUsage = string(data[1:3])
	h.Algorithm = data[3]
	h.ModeOfUse = data[4]
	h.KeyVersionNum = string(data[5:7])
	h.Exportability = data[7]
	h.OptionalBlocks = (data[8]-'0')*10 + (data[9] - '0')
	h.KeyContext = data[10]
	return nil
}
