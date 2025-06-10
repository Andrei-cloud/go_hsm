// filepath: pkg/keyblocklmk/cmac.go
// Implements AES-CMAC operations for keyblocklmk package.
package keyblocklmk

import (
	"crypto/aes"
	"fmt"
)

// computeAESCMAC computes the AES CMAC of data using key K (16 or 32 bytes for AES-128/256).
func computeAESCMAC(key []byte, data []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("AES cipher init failed: %v", err)
	}
	blockSize := block.BlockSize()

	// Generate subkeys K1 and K2.
	zero := make([]byte, blockSize)
	L := make([]byte, blockSize)
	block.Encrypt(L, zero)
	K1 := subkeyGenerate(L)
	K2 := subkeyGenerate(K1)

	var lastBlock []byte
	dataLen := len(data)
	if dataLen == 0 || dataLen%blockSize != 0 {
		// padding required.
		padLen := blockSize
		if dataLen%blockSize != 0 {
			padLen = dataLen % blockSize
		}
		padded := make([]byte, blockSize)
		copy(padded, data[dataLen-padLen:])
		padded[padLen] = 0x80

		lastBlock = xorBlock(padded, K2)
		data = data[:dataLen-padLen]
	} else {
		// no padding for full block.
		lastBlock = xorBlock(data[dataLen-blockSize:], K1)
		data = data[:dataLen-blockSize]
	}

	// CBC-MAC with IV = zero.
	X := make([]byte, blockSize)
	for i := 0; i < len(data); i += blockSize {
		blockIn := xorBlock(X, data[i:i+blockSize])
		block.Encrypt(X, blockIn)
	}

	// process final block.
	blockIn := xorBlock(X, lastBlock)
	block.Encrypt(X, blockIn)

	mac := make([]byte, blockSize)
	copy(mac, X)

	return mac, nil
}

// subkeyGenerate shifts block left by 1 bit and XORs with Rb if MSB was set.
func subkeyGenerate(b []byte) []byte {
	const Rb = 0x87
	n := len(b)
	out := make([]byte, n)
	carry := byte(0)

	for i := n - 1; i >= 0; i-- {
		out[i] = (b[i] << 1) | carry
		carry = (b[i] >> 7) & 0x01
	}

	if (b[0] & 0x80) != 0 {
		out[n-1] ^= Rb
	}

	return out
}

// xorBlock XORs two equal-length byte slices.
func xorBlock(a, b []byte) []byte {
	n := len(a)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}

	return out
}
