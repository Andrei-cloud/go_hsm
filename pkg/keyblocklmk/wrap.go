// Package and imports.
package keyblocklmk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
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
	plain := append(lengthField, key...)

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
		return nil, fmt.Errorf("header length invalid")
	}

	cipherBlock, err := aes.NewCipher(kbek)
	if err != nil {
		return nil, fmt.Errorf("AES cipher init failed: %v", err)
	}
	iv := headerBytes
	cbc := cipher.NewCBCEncrypter(cipherBlock, iv)
	ciphertext := make([]byte, len(plain))
	cbc.CryptBlocks(ciphertext, plain)

	// compute AES-CMAC over header, optional blocks, and ciphertext.
	macInput := make([]byte, 0, len(headerBytes)+len(ciphertext))
	macInput = append(macInput, headerBytes...)
	for _, opt := range optBlocks {
		macInput = append(macInput, opt.Marshal()...)
	}
	macInput = append(macInput, ciphertext...)
	authFull, err := computeAESCMAC(kbak, macInput)
	if err != nil {
		return nil, fmt.Errorf("CMAC computation failed: %v", err)
	}
	authField := authFull
	if format == 'S' {
		authField = authFull[:8]
	}

	// assemble final key block: header, optional blocks, ciphertext, and MAC.
	result := make([]byte, 0, len(headerBytes)+len(ciphertext)+len(authField))
	result = append(result, headerBytes...)
	for _, opt := range optBlocks {
		result = append(result, opt.Marshal()...)
	}
	result = append(result, ciphertext...)
	result = append(result, authField...)

	return result, nil
}
