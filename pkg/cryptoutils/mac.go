package cryptoutils

import (
	"crypto/aes"
	"crypto/des"
	"errors"
	"fmt"
)

// CalculateMAC computes an s-byte MAC (4 ≤ s ≤ 8) over msg using
// ISO/IEC 9797-1 CBC-DES Method 1 or 3 (algo == 1 or 3).
// ks must be 8 bytes (single-DES) or 16 bytes (two-key DES: k1||k2).
// s is the truncation length in bytes
// msg is already padded data.
func CalculateMAC(msg, ks []byte, s, algo int) ([]byte, error) {
	if s < 4 || s > 8 {
		return nil, fmt.Errorf("invalid MAC length %d", s)
	}
	if len(ks) != 8 && len(ks) != 16 {
		return nil, fmt.Errorf("ks must be 8 or 16 bytes, got %d", len(ks))
	}

	// 1. split into 8-byte blocks
	blocks := Chunk(msg, 8)

	// 2. CBC-3DES with k1 (prepared as triple-length) and zero IV
	h := make([]byte, 8)
	k1 := ks[:8]
	cipher1, err := des.NewTripleDESCipher(PrepareTripleDESKey(k1))
	if err != nil {
		return nil, err
	}
	for _, x := range blocks {
		xorIn, err := XORBytes(x, h)
		if err != nil {
			return nil, err
		}
		cipher1.Encrypt(h, xorIn)
	}

	// 3. Final transform
	var result []byte
	switch {
	case algo == 1, len(ks) == 8:
		// Alg 1: just take h
		result = h
	case algo == 3:
		k2 := ks[8:16]
		cipher2, err := des.NewTripleDESCipher(PrepareTripleDESKey(k2))
		if err != nil {
			return nil, err
		}
		tmp := make([]byte, 8)
		cipher2.Decrypt(tmp, h)
		cipher1.Encrypt(tmp, tmp)
		result = tmp
	default:
		return nil, errors.New("unknown algorithm, must be 1 or 3")
	}

	return result[:s], nil
}

// CMAC computes an s-byte AES-CMAC (4 ≤ s ≤ 8) over msg using key ks.
// Implements ISO/IEC 9797-1 Algorithm 5 (CMAC).
func CMAC(msg, ks []byte, s int) ([]byte, error) {
	const blockSize = aes.BlockSize // 16
	if s < 4 || s > 8 {
		return nil, fmt.Errorf("invalid MAC length %d", s)
	}
	if len(ks) != 16 && len(ks) != 24 && len(ks) != 32 {
		return nil, fmt.Errorf("AES key must be 16/24/32 bytes, got %d", len(ks))
	}

	// 1. derive subkeys k1, k2
	k1, k2, err := deriveSubkeys(ks)
	if err != nil {
		return nil, err
	}

	// 2. pad & mask final block
	var blocks [][]byte
	if len(msg)%blockSize == 0 {
		blocks = Chunk(msg, blockSize)
		last, err := XORBytes(blocks[len(blocks)-1], k1)
		if err != nil {
			return nil, err
		}
		blocks[len(blocks)-1] = last
	} else {
		padded := padISO7816_4(msg, blockSize)
		blocks = Chunk(padded, blockSize)
		last, err := XORBytes(blocks[len(blocks)-1], k2)
		if err != nil {
			return nil, err
		}
		blocks[len(blocks)-1] = last
	}

	// 3. CBC-AES with zero IV
	cipherBlock, err := aes.NewCipher(ks)
	if err != nil {
		return nil, err
	}
	h := make([]byte, blockSize)
	for _, x := range blocks {
		xorIn, err := XORBytes(x, h)
		if err != nil {
			return nil, err
		}
		cipherBlock.Encrypt(h, xorIn)
	}

	return h[:s], nil
}

// deriveSubkeys generates AES-CMAC subkeys k1, k2 per NIST SP 800-38B.
func deriveSubkeys(key []byte) ([]byte, []byte, error) {
	const blockSize = aes.BlockSize
	cipherBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	zero := make([]byte, blockSize)
	l := make([]byte, blockSize)
	cipherBlock.Encrypt(l, zero)

	// Rb constant
	const rb = 0x87

	k1 := make([]byte, blockSize)
	var carry byte
	// k1 = l << 1
	for i := blockSize - 1; i >= 0; i-- {
		b := l[i]
		k1[i] = (b << 1) | carry
		carry = (b >> 7) & 1
	}
	// if msb(l) == 1, k1 ^= Rb
	if (l[0] >> 7) == 1 {
		k1[blockSize-1] ^= rb
	}

	k2 := make([]byte, blockSize)
	carry = 0
	// k2 = k1 << 1
	for i := blockSize - 1; i >= 0; i-- {
		b := k1[i]
		k2[i] = (b << 1) | carry
		carry = (b >> 7) & 1
	}
	// if msb(k1) == 1, k2 ^= Rb
	if (k1[0] >> 7) == 1 {
		k2[blockSize-1] ^= rb
	}

	return k1, k2, nil
}
