package keyblocklmk

import (
	"errors"
	"fmt"
)

// Header represents the 16-byte Key Block Header for Thales 'S' format.
type Header struct {
	Version        byte   // Key Block Version ID (byte 0: "0" for 3-DES, "1" for AES).
	KeyUsage       string // 2-byte usage code (bytes 5-6).
	Algorithm      byte   // Algorithm character (byte 7).
	ModeOfUse      byte   // Mode of use (byte 8).
	KeyVersionNum  string // 2-digit key version number (bytes 9-10).
	Exportability  byte   // Exportability (byte 11).
	OptionalBlocks byte   // Number of optional header blocks (bytes 12-13: 0–99).
	KeyContext     byte   // LMK identifier (bytes 14-15).
}

// toBytes serializes the Header into its 16-byte representation.
// Note: This creates a temporary header for encryption IV purposes.
// The actual key block length (bytes 1-4) will be set during final assembly.
func (h Header) toBytes() ([]byte, error) {
	if len(h.KeyUsage) != 2 || len(h.KeyVersionNum) != 2 {
		return nil, errors.New("key usage and KeyVersionNum must be 2 characters each")
	}
	b := make([]byte, 16)
	b[0] = h.Version
	// Bytes 1-4: Key Block Length - set to "0000" for now, will be updated during assembly.
	copy(b[1:5], []byte("0000"))
	copy(b[5:7], []byte(h.KeyUsage))
	b[7] = h.Algorithm
	b[8] = h.ModeOfUse
	copy(b[9:11], []byte(h.KeyVersionNum))
	b[11] = h.Exportability
	b[12] = '0' + (h.OptionalBlocks / 10)
	b[13] = '0' + (h.OptionalBlocks % 10)
	b[14] = '0' + (h.KeyContext / 10)
	b[15] = '0' + (h.KeyContext % 10)

	return b, nil
}

// fromBytes parses a 16-byte slice into a Header.
func (h *Header) fromBytes(data []byte) error {
	if len(data) != 16 {
		return fmt.Errorf("header must be 16 bytes, got %d", len(data))
	}
	h.Version = data[0]
	// Skip bytes 1-4 (Key Block Length) as they're calculated during assembly.
	h.KeyUsage = string(data[5:7])
	h.Algorithm = data[7]
	h.ModeOfUse = data[8]
	h.KeyVersionNum = string(data[9:11])
	h.Exportability = data[11]
	h.OptionalBlocks = (data[12]-'0')*10 + (data[13] - '0')
	h.KeyContext = (data[14]-'0')*10 + (data[15] - '0')

	return nil
}
