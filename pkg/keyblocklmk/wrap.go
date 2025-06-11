// Package and imports.
package keyblocklmk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
)

// WrapKeyBlock encrypts a clear key under the LMK in a key block format ('S' or 'R').
func WrapKeyBlock(
	lmk []byte,
	header Header,
	optBlocks []OptionalBlock,
	key []byte,
	format rune,
) ([]byte, error) {
	// derive encryption and MAC keys.
	kbek, kbak, err := deriveEncryptionAndMACKeys(lmk, len(lmk))
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %v", err)
	}

	// build length-prefixed plaintext.
	keyBits := len(key) * 8
	lengthField := []byte{byte(keyBits >> 8), byte(keyBits & 0xFF)}
	plain := slices.Concat(lengthField, key)

	// apply TR-31 padding to multiple of AES block size.
	blockSize := aes.BlockSize
	padLen := blockSize - (len(plain) % blockSize)
	if padLen == blockSize {
		padLen = 0
	}

	if padLen > 0 {
		padding := make([]byte, padLen)
		if _, err := rand.Read(padding); err != nil {
			return nil, fmt.Errorf("random pad generation failed: %v", err)
		}

		plain = append(plain, padding...)
	}

	// encrypt plaintext under KBEK using AES-CBC with IV = header bytes.
	headerBytes, err := header.toBytes()
	if err != nil {
		return nil, err
	}
	if len(headerBytes) != blockSize {
		return nil, errors.New("header length invalid")
	}

	cipherBlock, err := aes.NewCipher(kbek)
	if err != nil {
		return nil, fmt.Errorf("aes cipher init failed: %v", err)
	}
	iv := headerBytes
	cbc := cipher.NewCBCEncrypter(cipherBlock, iv)
	ciphertext := make([]byte, len(plain))
	cbc.CryptBlocks(ciphertext, plain)

	// assemble final key block: header, optional blocks, ciphertext, and MAC.
	// First, calculate the total length excluding the length field itself
	optionalBlocksSize := 0
	for _, opt := range optBlocks {
		optionalBlocksSize += len(opt.Marshal())
	}

	authFieldSize := aes.BlockSize
	if format == 'S' {
		authFieldSize = 8
	}

	totalLen := len(headerBytes) + optionalBlocksSize + len(ciphertext) + authFieldSize

	// Update the header with the correct length before computing MAC
	lengthStr := fmt.Sprintf("%04d", totalLen)
	copy(headerBytes[1:5], []byte(lengthStr))

	// Now compute AES-CMAC over header, optional blocks, and ciphertext with correct length.
	macInput := make([]byte, 0, len(headerBytes)+len(ciphertext)+optionalBlocksSize)
	macInput = append(macInput, headerBytes...)
	for _, opt := range optBlocks {
		macInput = append(macInput, opt.Marshal()...)
	}
	macInput = append(macInput, ciphertext...)
	authFull, err := computeAESCMAC(kbak, macInput)
	if err != nil {
		return nil, fmt.Errorf("cmac computation failed: %v", err)
	}
	authField := authFull
	if format == 'S' {
		authField = authFull[:8]
	}

	// Assemble the final result
	result := make([]byte, 0, totalLen)
	result = append(result, headerBytes...)
	for _, opt := range optBlocks {
		optBytes := opt.Marshal()
		result = append(result, optBytes...)
	}
	result = append(result, ciphertext...)
	result = append(result, authField...)

	return result, nil
}
