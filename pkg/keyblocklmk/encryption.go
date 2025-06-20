package keyblocklmk

import (
	"crypto/aes"
	"fmt"
)

// deriveEncryptionAndMACKeys derives the KBEK and KBAK from the LMK using AES-CMAC per ISO 20038.
func deriveEncryptionAndMACKeys(lmk []byte, keyLenBytes int) ([]byte, []byte, error) {
	const (
		usageEnc uint16 = 0x0000 // encryption
		usageMac uint16 = 0x0001 // authentication
		algID    uint16 = 0x0004 // AES-256
	)
	keyLenBits := uint16(keyLenBytes * 8)
	iters := int((keyLenBits + 127) / 128)

	derive := func(usage uint16) ([]byte, error) {
		out := make([]byte, 0, iters*aes.BlockSize)
		for cnt := 1; cnt <= iters; cnt++ {
			// build 16-byte derivation input
			blk := make([]byte, aes.BlockSize)
			blk[0] = byte(cnt)
			blk[1] = byte(usage >> 8)
			blk[2] = byte(usage)
			blk[3] = 0x00
			blk[4] = byte(algID >> 8)
			blk[5] = byte(algID)
			blk[6] = byte(keyLenBits >> 8)
			blk[7] = byte(keyLenBits)
			// bytes 8-15 remain zero

			mac, err := computeAESCMAC(lmk, blk)
			if err != nil {
				return nil, fmt.Errorf("aes-cmac derivation failed: %v", err)
			}

			out = append(out, mac...)
		}

		return out[:keyLenBytes], nil
	}

	kbek, err := derive(usageEnc)
	if err != nil {
		return nil, nil, err
	}
	kbak, err := derive(usageMac)
	if err != nil {
		return nil, nil, err
	}

	return kbek, kbak, nil
}
