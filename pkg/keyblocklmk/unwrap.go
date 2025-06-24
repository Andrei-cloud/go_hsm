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

// UnwrapKeyBlock decrypts a key block using the LMK and returns the Header, clear key,
// the received MAC, and the computed MAC, for diagnostics.
func UnwrapKeyBlock(lmk, keyBlock []byte) (*Header, []byte, []byte, []byte, error) {
	// Store first byte as format and keyBlockStr from next byte.
	if len(keyBlock) == 0 {
		return nil, nil, nil, nil, errors.New("key block is empty")
	}

	_ = keyBlock[0]
	keyBlockStr := string(keyBlock[1:])

	var (
		header     Header
		macInput   []byte
		cipherText []byte
		recvMac    []byte
		macLen     int
	)

	// Input should always be binary.
	binaryKeyBlock := []byte(keyBlockStr)

	// Minimum length: 16-byte header + 8-byte MAC.
	if len(binaryKeyBlock) < 16+8 {
		return nil, nil, nil, nil, errors.New("key block too short")
	}

	if err := header.fromBytes(binaryKeyBlock[:16]); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("invalid header: %v", err)
	}

	macLen = aes.BlockSize // 16 bytes for CMAC

	// Parse optional blocks.
	offset := 16
	optCount := int(header.OptionalBlocks)
	for i := 0; i < optCount; i++ {
		if offset+3 > len(binaryKeyBlock) {
			return nil, nil, nil, nil, errors.New("truncated optional block")
		}
		length := int(binaryKeyBlock[offset+2])
		blockEnd := offset + 3 + length
		if blockEnd > len(binaryKeyBlock) {
			return nil, nil, nil, nil, errors.New("optional block length out of range")
		}
		offset = blockEnd
	}

	// Extract ciphertext and MAC.
	if len(binaryKeyBlock) < offset+macLen {
		return nil, nil, nil, nil, errors.New("key block data too short for MAC")
	}

	cipherText = binaryKeyBlock[offset : len(binaryKeyBlock)-macLen]
	recvMac = binaryKeyBlock[len(binaryKeyBlock)-macLen:]

	// MAC input is binary representation.
	macInput = make([]byte, 0, offset+len(cipherText))
	macInput = append(macInput, binaryKeyBlock[:offset]...)
	macInput = append(macInput, cipherText...)

	// Derive KBEK and KBAK.
	kbek, kbak, err := deriveEncryptionAndMACKeys(lmk, len(lmk))
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// Compute CMAC on the prepared MAC input.
	calcFull, err := computeAESCMAC(kbak, macInput)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("cmac computation failed: %v", err)
	}

	macCalc := calcFull[:macLen/2]

	binRecvMac, err := hex.DecodeString(string(recvMac))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("invalid received MAC: %v", err)
	}
	// Verify MAC.
	if !bytes.Equal(binRecvMac, macCalc) {
		return nil, nil, recvMac, macCalc, errors.New("mac verification failed")
	}

	// Decrypt ciphertext using AES-CBC with IV = header bytes.
	headerBytes, err := header.toBytes()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	cipherBlockObj, err := aes.NewCipher(kbek)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("aes cipher init failed: %v", err)
	}
	binCipherText, err := hex.DecodeString(string(cipherText))
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("invalid ciphertext hex: %v", err)
	}

	cbc := cipher.NewCBCDecrypter(cipherBlockObj, headerBytes)
	plainPadded := make([]byte, len(binCipherText))
	cbc.CryptBlocks(plainPadded, binCipherText)

	// Remove length prefix and padding.
	if len(plainPadded) < 2 {
		return nil, nil, nil, nil, errors.New("decrypted data too short")
	}

	keyBits := int(plainPadded[0])<<8 | int(plainPadded[1])
	expectedBytes := (keyBits + 7) / 8

	if expectedBytes > len(plainPadded)-2 {
		return nil, nil, nil, nil, errors.New("invalid key length in data")
	}

	clearKey := plainPadded[2 : 2+expectedBytes]

	return &header, clearKey, recvMac, macCalc, nil
}
