// Package variantlmk emulates the Thales payShield Variant LMK scheme in Go.
package variantlmk

import (
	"crypto/des"
	"encoding/hex"
	"errors"
	"fmt"
)

var VariantMap = map[int]byte{
	1: 0xA6,
	2: 0x5A,
	3: 0x6A,
	4: 0xDE,
	5: 0x2B,
	6: 0x50,
	7: 0x74,
	8: 0x9C,
	9: 0xFA,
}

type LMKPair struct {
	Left  []byte
	Right []byte
}

type LMKSet [20]LMKPair

func (lmk LMKPair) ApplyVariant(variantID int) (LMKPair, error) {
	v, ok := VariantMap[variantID]
	if !ok {
		return LMKPair{}, fmt.Errorf("unknown variant: %d", variantID)
	}
	copyL := make([]byte, len(lmk.Left))
	copyR := make([]byte, len(lmk.Right))
	copy(copyL, lmk.Left)
	copy(copyR, lmk.Right)
	copyL[0] ^= v

	return LMKPair{Left: copyL, Right: copyR}, nil
}

func EncryptUnderVariantLMK(inputKey []byte, pair LMKPair, schemeTag byte) ([]byte, error) {
	var variants []byte
	switch schemeTag {
	case 'U':
		if len(inputKey) != 16 {
			return nil, errors.New("double-length key required for scheme U")
		}
		variants = []byte{0xA6, 0x5A}
	case 'T':
		if len(inputKey) != 24 {
			return nil, errors.New("triple-length key required for scheme T")
		}
		variants = []byte{0x6A, 0xDE, 0x2B}
	default:

		return nil, fmt.Errorf("unknown scheme tag: %c", schemeTag)
	}

	encrypted := make([]byte, 0, len(inputKey))
	for i, v := range variants {
		variantLMK := make([]byte, 16)
		copy(variantLMK, pair.Left)
		copy(variantLMK[8:], pair.Right)
		variantLMK[8] ^= v

		variantLMK = append(variantLMK, variantLMK[:8]...)
		block, err := des.NewTripleDESCipher(variantLMK)
		if err != nil {
			return nil, err
		}
		segment := inputKey[i*8 : (i+1)*8]
		dst := make([]byte, 8)
		block.Encrypt(dst, segment)
		encrypted = append(encrypted, dst...)
	}

	return encrypted, nil
}

func LoadLMKFromHex(leftHex, rightHex string) (LMKPair, error) {
	left, err := hex.DecodeString(leftHex)
	if err != nil || len(left) != 8 {
		return LMKPair{}, errors.New("invalid left hex")
	}
	right, err := hex.DecodeString(rightHex)
	if err != nil || len(right) != 8 {
		return LMKPair{}, errors.New("invalid right hex")
	}

	return LMKPair{Left: left, Right: right}, nil
}

// DecryptUnderVariantLMK decrypts an input key that was encrypted under a variant LMK pair using a specific scheme.
// The provided LMKPair should already have the key-type specific variant applied.
func DecryptUnderVariantLMK(encryptedKey []byte, pair LMKPair, schemeTag byte) ([]byte, error) {
	var variants []byte
	switch schemeTag {
	case 'U':
		if len(encryptedKey) != 16 {
			return nil, errors.New("double-length encrypted key required for scheme U")
		}
		variants = []byte{0xA6, 0x5A}
	case 'T':
		if len(encryptedKey) != 24 {
			return nil, errors.New("triple-length encrypted key required for scheme T")
		}
		variants = []byte{0x6A, 0xDE, 0x2B}
	default:

		return nil, fmt.Errorf("unknown scheme tag: %c", schemeTag)
	}

	decrypted := make([]byte, 0, len(encryptedKey))
	for i, v := range variants {
		// Create the specific LMK for this part of the key.
		variantLMKForKeyPart := make([]byte, 16)
		copy(variantLMKForKeyPart, pair.Left)
		copy(variantLMKForKeyPart[8:], pair.Right)
		variantLMKForKeyPart[8] ^= v // Apply scheme variant to the first byte of the right half.

		// Prepare 3DES key (K1K2K1).
		variantLMKForKeyPart = append(variantLMKForKeyPart, variantLMKForKeyPart[:8]...)
		desKey := variantLMKForKeyPart
		block, err := des.NewTripleDESCipher(desKey)
		if err != nil {
			return nil, fmt.Errorf("failed to create 3DES cipher for decryption: %w", err)
		}

		segment := encryptedKey[i*8 : (i+1)*8]
		dst := make([]byte, 8)
		block.Decrypt(dst, segment)
		decrypted = append(decrypted, dst...)
	}

	return decrypted, nil
}
