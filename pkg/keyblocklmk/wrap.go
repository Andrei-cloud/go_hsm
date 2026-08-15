// Package and imports.
package keyblocklmk

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// WrapKeyBlock encrypts a clear key under the LMK in Thales 'S' key block format.
//
// Example:
//
//	lmk := []byte{0x00, 0x01, 0x02, ...} // 32 bytes LMK
//	header := Header{
//		Version: 'S',
//		KeyUsage: "00",
//		Algorithm: 'A',
//		ModeOfUse: 'B',
//		KeyVersionNum: "00",
//		Exportability: 'N',
//		OptionalBlocks: 0,
//		KeyContext: '1',
//	}
//	clearKey := []byte{0x12, 0x34, 0x56, ...}
//	keyBlock, err := WrapKeyBlock(lmk, header, nil, clearKey)
//	if err != nil {
//		log.Fatal(err)
//	}
//	// keyBlock is the encrypted key block in ASCII format
func WrapKeyBlock(
	lmk []byte,
	header Header,
	optBlocks []OptionalBlock,
	key []byte,
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

	// Apply padding to multiple of AES block size.
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

	// Calculate optional blocks size for MAC calculation.
	optionalBlocksSize := 0
	for _, opt := range optBlocks {
		optionalBlocksSize += len(opt.Marshal())
	}
	// Prepare hex-encoded ciphertext for MAC calculation to match unwrap expectations.
	hexCiphertext := []byte(strings.ToUpper(hex.EncodeToString(ciphertext)))

	// Now compute AES-CMAC over header, optional blocks, and hex-encoded ciphertext.
	macInput := make([]byte, 0, len(headerBytes)+len(hexCiphertext)+optionalBlocksSize)
	macInput = append(macInput, headerBytes...)
	for _, opt := range optBlocks {
		macInput = append(macInput, opt.Marshal()...)
	}
	macInput = append(macInput, hexCiphertext...)
	authFull, err := computeAESCMAC(kbak, macInput)
	if err != nil {
		return nil, fmt.Errorf("cmac computation failed: %v", err)
	}
	// Use 8 bytes for Thales 'S' format.
	authField := authFull[:8]

	// Assemble the final result according to Thales 'S' specification:
	// - Header and optional blocks: ASCII format (not hex-encoded)
	// - Encrypted key data and MAC: ASCII hex encoded
	var result strings.Builder

	// Add key scheme tag for Thales format.
	result.WriteString("S")

	// Add header as ASCII characters (not hex-encoded).
	if _, err := result.Write(headerBytes); err != nil {
		return nil, fmt.Errorf("failed to write header bytes: %v", err)
	}

	// Add optional blocks as ASCII characters (not hex-encoded).
	for _, opt := range optBlocks {
		optBytes := opt.Marshal()
		if _, err := result.Write(optBytes); err != nil {
			return nil, fmt.Errorf("failed to write optional block: %v", err)
		}
	}

	// Add encrypted key data and MAC as ASCII hex encoded.
	result.WriteString(strings.ToUpper(hex.EncodeToString(ciphertext)))
	result.WriteString(strings.ToUpper(hex.EncodeToString(authField)))

	return []byte(result.String()), nil
}
