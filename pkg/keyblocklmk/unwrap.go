package keyblocklmk

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
)

// isHexString checks if a string contains only hex characters.
func isHexString(s string) bool {
	if len(s)%2 != 0 {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'A' && r <= 'F') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}

	return true
}

// UnwrapKeyBlock decrypts a key block using the LMK and returns the Header and clear key.
func UnwrapKeyBlock(lmk, keyBlock []byte) (*Header, []byte, error) {
	// Check for Thales key scheme tag "S" at the beginning (ASCII format)
	keyBlockStr := string(keyBlock)
	format := 'R' // Default to TR-31

	if keyBlockStr != "" && keyBlockStr[0] == 'S' {
		// Thales format with key scheme tag "S".
		format = 'S'
		keyBlockStr = keyBlockStr[1:] // Skip the "S" tag.
	}

	// For Thales format with mixed encoding:
	// - Header and optional blocks are ASCII characters
	// - Encrypted key data and MAC are hex-encoded
	var binaryKeyBlock []byte

	if format == 'S' {
		// Parse header directly as ASCII (16 bytes).
		if len(keyBlockStr) < 16 {
			return nil, nil, errors.New("key block too short for header")
		}
		headerBytes := []byte(keyBlockStr[:16])

		// Parse header to get optional block count.
		var header Header
		if err := header.fromBytes(headerBytes); err != nil {
			return nil, nil, fmt.Errorf("invalid header: %v", err)
		}
		// Calculate optional blocks length.
		asciiOffset := 16
		optCount := int(header.OptionalBlocks)
		for i := 0; i < optCount; i++ {
			if asciiOffset+3 > len(keyBlockStr) {
				return nil, nil, errors.New("truncated optional block")
			}
			length := int(keyBlockStr[asciiOffset+2])
			blockEnd := asciiOffset + 3 + length
			if blockEnd > len(keyBlockStr) {
				return nil, nil, errors.New("optional block length out of range")
			}
			asciiOffset = blockEnd
		}
		// Header and optional blocks are ASCII.
		headerAndOptBlocks := []byte(keyBlockStr[:asciiOffset])

		// Remaining data (encrypted key + MAC) is hex-encoded.
		hexEncodedData := keyBlockStr[asciiOffset:]
		if !isHexString(hexEncodedData) {
			return nil, nil, errors.New("encrypted data portion is not valid hex")
		}
		encryptedData, err := hex.DecodeString(hexEncodedData)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid hex-encoded encrypted data: %v", err)
		}
		// Combine header+optblocks with decoded encrypted data.
		binaryKeyBlock = make([]byte, 0, len(headerAndOptBlocks)+len(encryptedData))
		binaryKeyBlock = append(binaryKeyBlock, headerAndOptBlocks...)
		binaryKeyBlock = append(binaryKeyBlock, encryptedData...)
	} else {
		// For TR-31 format, input should always be binary.
		binaryKeyBlock = []byte(keyBlockStr)
	}

	// Minimum length: 16-byte header + 8-byte MAC.
	if len(binaryKeyBlock) < 16+8 {
		return nil, nil, errors.New("key block too short")
	}

	// Parse header.
	var header Header
	if err := header.fromBytes(binaryKeyBlock[:16]); err != nil {
		return nil, nil, fmt.Errorf("invalid header: %v", err)
	}

	// Determine MAC length by format.
	macLen := aes.BlockSize // 16 bytes for TR-31

	if format == 'S' || header.Version == 'S' {
		format = 'S'
		macLen = 8
	} else if len(binaryKeyBlock) >= 24 {
		// For version '1' (AES), we need to determine format another way.
		// Check if the total length suggests 8-byte MAC vs 16-byte MAC.
		// Calculate expected length with 8-byte MAC vs 16-byte MAC
		// This is a heuristic: if remainder after header is 8 mod 16, likely 8-byte MAC
		remainder := (len(binaryKeyBlock) - 16) % 16
		if remainder == 8 {
			format = 'S'
			macLen = 8
		}
	}

	// Parse optional blocks.
	var (
		offset   = 16
		optCount = int(header.OptionalBlocks)
	)
	for i := 0; i < optCount; i++ {
		if offset+3 > len(binaryKeyBlock) {
			return nil, nil, errors.New("truncated optional block")
		}

		length := int(binaryKeyBlock[offset+2])
		blockEnd := offset + 3 + length
		if blockEnd > len(binaryKeyBlock) {
			return nil, nil, errors.New("optional block length out of range")
		}

		offset = blockEnd
	}

	// Extract ciphertext and MAC.
	if len(binaryKeyBlock) < offset+macLen {
		return nil, nil, errors.New("key block data too short for MAC")
	}

	cipherText := binaryKeyBlock[offset : len(binaryKeyBlock)-macLen]
	recvMac := binaryKeyBlock[len(binaryKeyBlock)-macLen:]

	// Derive KBEK and KBAK.
	kbek, kbak, err := deriveEncryptionAndMACKeys(lmk, len(lmk))
	if err != nil {
		return nil, nil, err
	}

	// Compute CMAC on header, optional blocks, and ciphertext.
	macInput := make([]byte, offset)
	copy(macInput, binaryKeyBlock[:offset])

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
