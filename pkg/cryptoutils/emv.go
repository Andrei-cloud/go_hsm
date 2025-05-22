package cryptoutils

import (
	"crypto/aes"
	"crypto/des"
	"crypto/sha1"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// DeriveICCKey derives the k-bit ICC Master Key per EMV A1.4 (Option A, B or C).
func DeriveICCKey(pan, panSeq string, imk []byte, option string) ([]byte, error) {
	switch strings.ToUpper(option) {
	case "A":
		return deriveOptionA(pan, panSeq, imk)
	case "B":
		return deriveOptionB(pan, panSeq, imk)
	case "C":
		return deriveOptionC(pan, panSeq, imk)
	default:
		return nil, fmt.Errorf("unsupported derivation option %q", option)
	}
}

// --- Option A (3DES only) ---------------------------------------------------.

func deriveOptionA(pan, panSeq string, imk []byte) ([]byte, error) {
	if panSeq == "" {
		panSeq = "00"
	}
	x := pan + panSeq
	// take rightmost 16 digits, or pad left with '0'.
	if len(x) < 16 {
		x = strings.Repeat("0", 16-len(x)) + x
	} else if len(x) > 16 {
		x = x[len(x)-16:]
	}
	// BCD-encode 16 digits → 8 bytes.
	y, err := bcdEncode(x)
	if err != nil {
		return nil, err
	}

	return derive3DESKey(imk, y)
}

// --- Option B (3DES + SHA-1 decimalization) --------------------------------.

func deriveOptionB(pan, panSeq string, imk []byte) ([]byte, error) {
	// if PAN ≤ 16 digits, fall back to Option A.
	if len(pan) <= 16 {
		return deriveOptionA(pan, panSeq, imk)
	}
	if panSeq == "" {
		panSeq = "00"
	}
	// if PAN has odd digits, pad one '0' left.
	if len(pan)%2 != 0 {
		pan = "0" + pan
	}
	// Compose input for hashing.
	x := pan + panSeq
	// SHA-1 hash over ASCII digits.
	h := sha1.Sum([]byte(x))
	// decimalize into 16-digit string.
	y := decimalize(h[:])
	// BCD-encode → 8 bytes.
	yBcd, err := bcdEncode(y)
	if err != nil {
		return nil, err
	}

	return derive3DESKey(imk, yBcd)
}

// --- Option C (AES) ---------------------------------------------------------.

func deriveOptionC(pan, panSeq string, imk []byte) ([]byte, error) {
	if panSeq == "" {
		panSeq = "00"
	}

	x := pan + panSeq
	// pad or truncate to 32 digits → 16 bytes BCD
	if len(x) < 32 {
		x = strings.Repeat("0", 32-len(x)) + x
	} else if len(x) > 32 {
		x = x[len(x)-32:]
	}
	y, err := bcdEncode(x)
	if err != nil {
		return nil, err
	}

	blk1, err := aesECBEncryptBlock(imk, y)
	if err != nil {
		return nil, err
	}
	// if key size ≤ 128 bits, done
	if len(imk)*8 <= aes.BlockSize*8 {
		return blk1, nil
	}
	// else produce a second block at Y⊕FF..FF, concatenate, and left-slice to k bytes
	yXor := xor(y, bytesRepeat(0xFF, aes.BlockSize))
	blk2, err := aesECBEncryptBlock(imk, yXor)
	if err != nil {
		return nil, err
	}

	concat := slices.Concat(blk1, blk2)
	kb := len(imk) // bytes
	if len(concat) < kb {
		return nil, fmt.Errorf("AES derive: got %d bytes, need %d", len(concat), kb)
	}

	return concat[:kb], nil
}

// --- Helpers ---------------------------------------------------------------.

// derive3DESKey does ZL||ZR then applies odd-parity on each of the 16 bytes.
func derive3DESKey(imk, block8 []byte) ([]byte, error) {
	if len(block8) != des.BlockSize {
		return nil, errors.New("invalid block size for 3DES")
	}
	c, err := des.NewTripleDESCipher(imk)
	if err != nil {
		return nil, err
	}
	zl := make([]byte, des.BlockSize)
	c.Encrypt(zl, block8)
	tmp := make([]byte, des.BlockSize)
	for i := range block8 {
		tmp[i] = block8[i] ^ 0xFF
	}
	zr := make([]byte, des.BlockSize)
	c.Encrypt(zr, tmp)
	z := slices.Concat(zl, zr)
	z = FixKeyParity(z)

	return z, nil
}

// aesECBEncryptBlock encrypts exactly one 16-byte block under AES-ECB.
func aesECBEncryptBlock(key, blk []byte) ([]byte, error) {
	if len(blk) != aes.BlockSize {
		return nil, errors.New("invalid block size for AES")
	}
	c, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, aes.BlockSize)
	c.Encrypt(out, blk)

	return out, nil
}

// bcdEncode converts an even-length string of decimal digits into BCD bytes.
func bcdEncode(digits string) ([]byte, error) {
	if len(digits)%2 != 0 {
		return nil, errors.New("must be even number of digits for BCD")
	}
	out := make([]byte, len(digits)/2)
	for i := range out {
		hi := digits[2*i] - '0'
		lo := digits[2*i+1] - '0'
		if hi > 9 || lo > 9 {
			return nil, fmt.Errorf("invalid digit in %q", digits)
		}

		out[i] = hi<<4 | lo
	}

	return out, nil
}

// decimalize picks the first 16 decimal nibbles from hash, then applies the EMV
// table A→0, B→1…F→5 to fill to 16 if needed.
func decimalize(hash []byte) string {
	// extract 40 nibbles.
	nibs := make([]byte, 0, len(hash)*2)
	for _, b := range hash {
		nibs = append(nibs, b>>4, b&0xF)
	}

	var out []byte
	// 1st pass: collect <10.
	for _, n := range nibs {
		if n < 10 {
			out = append(out, '0'+n)
			if len(out) == 16 {
				return string(out)
			}
		}
	}
	// 2nd pass: map A–F → 0–5.
	mapTbl := map[byte]byte{0xA: 0, 0xB: 1, 0xC: 2, 0xD: 3, 0xE: 4, 0xF: 5}
	for _, n := range nibs {
		if n >= 10 {
			out = append(out, '0'+mapTbl[n])
			if len(out) == 16 {
				break
			}
		}
	}

	return string(out)
}

// xor two equal-length slices.
func xor(a, b []byte) []byte {
	n := len(a)
	out := make([]byte, n)
	for i := 0; i < n; i++ {
		out[i] = a[i] ^ b[i]
	}

	return out
}

// bytesRepeat returns a new slice of length n filled with b.
func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}

	return out
}

// --- Example usage ---------------------------------------------------------
//
//	func main() {
//	  imk, _ := hex.DecodeString("0123456789ABCDEF0123456789ABCDEF")
//	  // Option A
//	  mkA, err := DeriveICCKey("4000123412341234", "01", imk, "A")
//	  fmt.Printf("MK(A) = %X err=%v\n", mkA, err)
//	  // Option B
//	  mkB, err := DeriveICCKey("1234567890123456789012345", "02", imk, "B")
//	  fmt.Printf("MK(B) = %X err=%v\n", mkB, err)
//	  // Option C (AES-128)
//	  aesKey, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF")
//	  mkC, err := DeriveICCKey("4000123412341234", "01", aesKey, "C")
//	  fmt.Printf("MK(C) = %X err=%v\n", mkC, err)
//	}
//
// All three methods just follow the spec steps: BCD-encode your PAN || PSN, run the right block cipher(s),
// and—in the case of 3DES—set odd parity on every byte of the 16-byte result.
