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
	bs := block.BlockSize()

	// Generate subkeys K1 and K2
	zero := make([]byte, bs)
	l := make([]byte, bs)
	block.Encrypt(l, zero)
	k1 := subkeyGenerate(l)
	k2 := subkeyGenerate(k1)

	// Determine padding and last block
	n := len(data)
	nBlocks := 0
	if n == 0 {
		// one padded block
		nBlocks = 1
	} else {
		nBlocks = (n + bs - 1) / bs
	}

	// Prepare blocks
	blocks := make([][]byte, nBlocks)
	for i := 0; i < nBlocks; i++ {
		start := i * bs
		end := start + bs
		if end > n {
			end = n
		}
		blocks[i] = make([]byte, bs)
		copy(blocks[i], data[start:end])
	}

	// Process last block
	if n > 0 && n%bs == 0 {
		// complete block, XOR with K1.
		blocks[nBlocks-1] = xorBlock(blocks[nBlocks-1], k1)
	} else {
		// incomplete block or n==0, pad then XOR with K2.
		pad := make([]byte, bs)
		padPos := n % bs
		pad[padPos] = 0x80
		blocks[nBlocks-1] = xorBlock(blocks[nBlocks-1], pad)
		blocks[nBlocks-1] = xorBlock(blocks[nBlocks-1], k2)
	}

	// CBC-MAC calculation.
	x := make([]byte, bs)
	for _, blk := range blocks {
		x = xorBlock(x, blk)
		block.Encrypt(x, x)
	}
	mac := make([]byte, bs)
	copy(mac, x)

	return mac, nil
}

// subkeyGenerate shifts the block left by 1 bit and XORs with Rb if MSB was set.
func subkeyGenerate(b []byte) []byte {
	const rb = 0x87
	n := len(b)
	out := make([]byte, n)
	carry := byte(0)

	for i := n - 1; i >= 0; i-- {
		newCarry := b[i] >> 7
		out[i] = (b[i] << 1) | carry
		carry = newCarry
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
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}

	return out
}
