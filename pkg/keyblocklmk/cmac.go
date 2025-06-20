// filepath: pkg/keyblocklmk/cmac.go
// Implements AES-CMAC operations for keyblocklmk package.
package keyblocklmk

import (
	"crypto/aes"
	"fmt"
)

// computeAESCMAC computes the AES CMAC of data using key K (16 or 32 bytes for AES-128/256).
func computeAESCMAC(key, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("aes cipher init failed: %w", err)
	}
	blockSize := block.BlockSize()

	// Generate subkeys k1 and k2.
	// This follows RFC 4493, Section 2.3.
	zero := make([]byte, blockSize)
	l := make([]byte, blockSize)
	// L = AES-K(0^n).
	block.Encrypt(l, zero)

	k1 := subkeyGenerate(l)
	k2 := subkeyGenerate(k1)

	dataToProcessInCBC := data
	var lastBlockXORedWithKey []byte // This will be (M_n XOR K1) or (Padded_M_n XOR K2)

	switch {
	case len(data) == 0:
		// Case 1: Message length is 0 (M_len = 0).
		// Pad to one block (0x80 || 0...0) and XOR with K2.
		// The "message" for CBC processing is empty.
		// The final block to encrypt is ( (0x80 || 0...0) XOR K2 ) XOR IV (which is 0).
		padded := make([]byte, blockSize)
		padded[0] = 0x80 // M_last = M_n || 1 || 0...0
		lastBlockXORedWithKey = xorBlock(padded, k2)
		dataToProcessInCBC = []byte{} // Ensure CBC loop does not run.
	case len(data)%blockSize == 0:
		// Case 2: Message length is a non-zero multiple of block size (M_len > 0, M_len mod n = 0).
		// Last block is M_n. XOR with K1.
		// Process M_1 to M_{n-1} in CBC.
		lastBlockData := data[len(data)-blockSize:]
		lastBlockXORedWithKey = xorBlock(lastBlockData, k1)
		dataToProcessInCBC = data[:len(data)-blockSize]
	default:
		// Case 3: Message length is not a multiple of block size (M_len > 0, M_len mod n != 0).
		// Pad the last block (M_n || 1 || 0...0) and XOR with K2.
		// Process M_1 to M_{n-1} in CBC.
		lastPartialBlockLen := len(data) % blockSize

		padded := make([]byte, blockSize)
		copy(padded, data[len(data)-lastPartialBlockLen:])
		padded[lastPartialBlockLen] = 0x80
		// Remaining bytes of 'padded' are already zero.

		lastBlockXORedWithKey = xorBlock(padded, k2)
		dataToProcessInCBC = data[:len(data)-lastPartialBlockLen]
	}

	// CBC-MAC with IV = zero.
	// X_0 = 0^n
	// For i = 1 to n-1: X_i = AES-K( M_i XOR X_{i-1} )
	x := make([]byte, blockSize) // Chaining variable (X_i), starts as IV (zeros / X_0).
	for i := 0; i < len(dataToProcessInCBC); i += blockSize {
		blockIn := xorBlock(x, dataToProcessInCBC[i:i+blockSize]) // M_i XOR X_{i-1}
		block.Encrypt(x, blockIn)                                 // X_i = AES-K( M_i XOR X_{i-1} )
	}

	// Process final block.
	// T = AES-K( M_n^* XOR X_{n-1} )
	// where M_n^* is lastBlockXORedWithKey.
	finalInputToAES := xorBlock(x, lastBlockXORedWithKey)
	block.Encrypt(x, finalInputToAES) // Final encryption, result is T (the MAC).

	mac := make([]byte, blockSize)
	copy(mac, x)

	return mac, nil
}

// subkeyGenerate shifts block left by 1 bit and XORs with Rb if MSB was set.
func subkeyGenerate(b []byte) []byte {
	const rb = 0x87
	n := len(b)
	out := make([]byte, n)
	carry := byte(0)

	for i := n - 1; i >= 0; i-- {
		out[i] = (b[i] << 1) | carry
		carry = (b[i] >> 7) & 0x01
	}

	if (b[0] & 0x80) != 0 {
		out[n-1] ^= rb
	}

	return out
}

// xorBlock XORs two equal-length byte slices.
func xorBlock(a, b []byte) []byte {
	n := len(a)
	out := make([]byte, n)
	for i := range n {
		out[i] = a[i] ^ b[i]
	}

	return out
}
