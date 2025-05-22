// Package sessionkey provides EMV common session key derivation per A1.3.1.
package cryptoutils

import (
	"crypto/aes"
	"crypto/des"
	"fmt"
	"slices"
)

// DeriveSessionKey derives an EMV session key KS from master key km and
// diversification data r, following Annex A1.3.1 (common session key option).
//   - km: ICC Master Key (single, double or triple length)
//   - r:  diversification data (n bytes, where n = block size: 8 for DES, 16 for AES)
//
// For single-length km (len(km)==len(r)), returns E_km(r).
// For double-length (len(r)<len(km)<=2*len(r)), forms two variants f1,f2 and returns
// leftmost len(km) bytes of E_km(f1)||E_km(f2).
func DeriveSessionKey(km, r []byte) ([]byte, error) {
	n := len(r)
	klen := len(km)

	// single-block case: len(km) == len(r)
	if klen == n {
		out := make([]byte, n)
		switch n {
		case des.BlockSize:
			c, err := des.NewCipher(km)
			if err != nil {
				return nil, err
			}
			c.Encrypt(out, r)
		case aes.BlockSize:
			c, err := aes.NewCipher(km)
			if err != nil {
				return nil, err
			}
			c.Encrypt(out, r)
		default:
			return nil, fmt.Errorf("unsupported block size %d", n)
		}

		return out, nil
	}

	// multi-block case: n < len(km) <= 2*n
	if klen > n && klen <= 2*n {
		// prepare f1 = r0||r1||0xF0||r3..Rn-1
		f1 := make([]byte, n)
		f2 := make([]byte, n)
		copy(f1, r)
		copy(f2, r)
		if n >= 3 {
			f1[2] = 0xF0
			f2[2] = 0x0F
		} else {
			// if block too small, just alter last byte
			f1[n-1] ^= 0xF0
			f2[n-1] ^= 0x0F
		}

		blk1 := make([]byte, n)
		blk2 := make([]byte, n)
		switch n {
		case des.BlockSize:
			// DES3 for klen == 16 or 24
			c, err := des.NewTripleDESCipher(km)
			if err != nil {
				return nil, err
			}
			c.Encrypt(blk1, f1)
			c.Encrypt(blk2, f2)
		case aes.BlockSize:
			// AES ECB for 16-byte blocks
			c, err := aes.NewCipher(km)
			if err != nil {
				return nil, err
			}
			c.Encrypt(blk1, f1)
			c.Encrypt(blk2, f2)
		default:
			return nil, fmt.Errorf("unsupported block size %d", n)
		}

		concat := slices.Concat(blk1, blk2)
		if len(concat) < klen {
			return nil, fmt.Errorf(
				"derived output %d bytes shorter than key length %d",
				len(concat),
				klen,
			)
		}

		return concat[:klen], nil
	}

	return nil, fmt.Errorf("invalid key length %d for block size %d", klen, n)
}
