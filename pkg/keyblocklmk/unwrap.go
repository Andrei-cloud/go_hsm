package keyblocklmk

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
)

// UnwrapKeyBlock decrypts a key block using the LMK and returns the Header and clear key.
func UnwrapKeyBlock(lmk, keyBlock []byte) (*Header, []byte, error) {
	// Minimum length: 16-byte header + 8-byte MAC.
	if len(keyBlock) < 16+8 {
		return nil, nil, errors.New("key block too short")
	}

	// Parse header.
	var header Header
	if err := header.fromBytes(keyBlock[:16]); err != nil {
		return nil, nil, fmt.Errorf("invalid header: %v", err)
	}
	// Determine MAC length by format.
	// Check if this is a Thales 'S' format based on version field
	format := 'R'           // Default to TR-31
	macLen := aes.BlockSize // 16 bytes for TR-31

	if header.Version == 'S' {
		format = 'S'
		macLen = 8
	} else {
		// For version '1' (AES), we need to determine format another way.
		// Check if the total length suggests 8-byte MAC vs 16-byte MAC.
		if len(keyBlock) >= 24 { // minimum: 16 header + 8 MAC
			// Calculate expected length with 8-byte MAC vs 16-byte MAC
			// This is a heuristic: if remainder after header is 8 mod 16, likely 8-byte MAC
			remainder := (len(keyBlock) - 16) % 16
			if remainder == 8 {
				format = 'S'
				macLen = 8
			}
		}
	}
	// Parse optional blocks.
	offset := 16
	optCount := int(header.OptionalBlocks)
	for i := 0; i < optCount; i++ {
		if offset+3 > len(keyBlock) {
			return nil, nil, errors.New("truncated optional block")
		}

		length := int(keyBlock[offset+2])
		blockEnd := offset + 3 + length
		if blockEnd > len(keyBlock) {
			return nil, nil, errors.New("optional block length out of range")
		}

		offset = blockEnd
	}

	// Extract ciphertext and MAC.
	if len(keyBlock) < offset+macLen {
		return nil, nil, errors.New("key block data too short for MAC")
	}

	cipherText := keyBlock[offset : len(keyBlock)-macLen]
	recvMac := keyBlock[len(keyBlock)-macLen:]

	// Derive KBEK and KBAK.
	kbek, kbak, err := deriveEncryptionAndMACKeys(lmk, len(lmk))
	if err != nil {
		return nil, nil, err
	}

	// Compute CMAC on header, optional blocks, and ciphertext.
	macInput := make([]byte, offset)
	copy(macInput, keyBlock[:offset])

	calcFull, err := computeAESCMAC(kbak, append(macInput, cipherText...))
	if err != nil {
		return nil, nil, fmt.Errorf("cmac computation failed: %v", err)
	}

	macCalc := calcFull
	if format == 'S' {
		macCalc = calcFull[:8]
	}

	// Verify MAC.
	if !bytes.Equal(recvMac, macCalc) {
		return nil, nil, errors.New("mac verification failed")
	}

	// Decrypt ciphertext using AES-CBC with IV = header bytes.
	headerBytes, err := header.toBytes()
	if err != nil {
		return nil, nil, err
	}

	cipherBlockObj, err := aes.NewCipher(kbek)
	if err != nil {
		return nil, nil, fmt.Errorf("aes cipher init failed: %v", err)
	}

	cbc := cipher.NewCBCDecrypter(cipherBlockObj, headerBytes)
	plainPadded := make([]byte, len(cipherText))
	cbc.CryptBlocks(plainPadded, cipherText)

	// Remove length prefix and padding.
	if len(plainPadded) < 2 {
		return nil, nil, errors.New("decrypted data too short")
	}

	keyBits := int(plainPadded[0])<<8 | int(plainPadded[1])
	expectedBytes := (keyBits + 7) / 8

	if expectedBytes > len(plainPadded)-2 {
		return nil, nil, errors.New("invalid key length in data")
	}

	clearKey := plainPadded[2 : 2+expectedBytes]

	return &header, clearKey, nil
}
