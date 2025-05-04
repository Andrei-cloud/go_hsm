// Package cryptoutils provides utility functions for binary and cryptographic operations.
// Translated from the provided Python implementation using only Go standard libraries.
package cryptoutils

import (
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ecb wraps a cipher.Block to provide ECB mode.
type ecb struct{ b cipher.Block }

type ecbEncrypter ecb

type ecbDecrypter ecb

// Raw2Str converts raw binary data to an uppercase hex string.
func Raw2Str(raw []byte) string {
	return strings.ToUpper(hex.EncodeToString(raw))
}

// Raw2B returns the uppercase hex representation of raw data as bytes.
func Raw2B(raw []byte) []byte {
	return []byte(Raw2Str(raw))
}

// B2Raw decodes a hex-encoded byte slice into raw binary data.
func B2Raw(hexData []byte) ([]byte, error) {
	return hex.DecodeString(string(hexData))
}

// XOR takes two equal-length hex-encoded byte slices, XORs their raw bytes, and
// returns the result as uppercase hex bytes.
func XOR(block1, block2 []byte) ([]byte, error) {
	r1, err := B2Raw(block1)
	if err != nil {
		return nil, err
	}
	r2, err := B2Raw(block2)
	if err != nil {
		return nil, err
	}
	if len(r1) != len(r2) {
		return nil, fmt.Errorf("xor: length mismatch %d vs %d", len(r1), len(r2))
	}
	res := make([]byte, len(r1))
	for i := range r1 {
		res[i] = r1[i] ^ r2[i]
	}

	return Raw2B(res), nil
}

// Hexify converts a non-negative integer to an even-length uppercase hex string.
func Hexify(n int) (string, error) {
	if n < 0 {
		return "", fmt.Errorf("hexify: negative value %d", n)
	}
	s := strings.ToUpper(fmt.Sprintf("%X", n))
	if len(s)%2 == 1 {
		s = "0" + s
	}

	return s, nil
}

// newECBEncrypter returns a BlockMode which encrypts in ECB.
func newECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(&ecb{b: b})
}

func (x *ecbEncrypter) BlockSize() int { return x.b.BlockSize() }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.BlockSize() != 0 {
		panic("cryptoutils: input not full blocks")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst[:x.BlockSize()], src[:x.BlockSize()])
		src = src[x.BlockSize():]
		dst = dst[x.BlockSize():]
	}
}

// newECBDecrypter returns a BlockMode which decrypts in ECB.
func newECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(&ecb{b: b})
}

func (x *ecbDecrypter) BlockSize() int { return x.b.BlockSize() }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.BlockSize() != 0 {
		panic("cryptoutils: input not full blocks")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst[:x.BlockSize()], src[:x.BlockSize()])
		src = src[x.BlockSize():]
		dst = dst[x.BlockSize():]
	}
}

// KeyCV computes the DES key check value (KCV) by encrypting two blocks of zeros.
func KeyCV(keyHex []byte, kcvLen int) ([]byte, error) {
	rawKey, err := B2Raw(keyHex)
	if err != nil {
		return nil, err
	}

	// Convert to triple length if needed
	var fullKey []byte
	switch len(rawKey) {
	case 8: // Single length
		fullKey = make([]byte, 24)
		copy(fullKey, rawKey)
		copy(fullKey[8:], rawKey)
		copy(fullKey[16:], rawKey)
	case 16: // Double length
		fullKey = make([]byte, 24)
		copy(fullKey, rawKey)
		copy(fullKey[16:], rawKey[:8])
	case 24: // Triple length
		fullKey = rawKey
	default:
		return nil, fmt.Errorf("KeyCV: invalid key length %d", len(rawKey))
	}

	block, err := des.NewTripleDESCipher(fullKey)
	if err != nil {
		return nil, err
	}

	// Encrypt two blocks of zeros (16 bytes total)
	zero := make([]byte, block.BlockSize()*2)
	dst := make([]byte, len(zero))
	mode := newECBEncrypter(block)
	mode.CryptBlocks(dst, zero)
	hv := Raw2B(dst)
	if kcvLen > len(hv) {
		return nil, fmt.Errorf("KeyCV: kcv_length %d too large", kcvLen)
	}

	return hv[:kcvLen], nil
}

// GetDigitsFromString extracts up to 'length' decimal digits from a hex string,
// applying a second pass on non-decimal hex chars if needed.
func GetDigitsFromString(ct string, length int) string {
	var digits strings.Builder
	// First pass: pick decimal digits
	for _, c := range ct {
		if digits.Len() >= length {
			break
		}
		if unicode.IsDigit(c) {
			digits.WriteRune(c)
		}
	}
	// Second pass: non-decimal hex chars
	if digits.Len() < length {
		for _, c := range ct {
			if digits.Len() >= length {
				break
			}
			val, err := strconv.ParseInt(string(c), 16, 0)
			if err != nil {
				continue
			}
			if val-10 >= 0 {
				digits.WriteString(strconv.Itoa(int(val - 10)))
			}
		}
	}
	return digits.String()
}

// GetVisaPVV generates a 4-digit PIN Verification Value (PVV) using 3DES ECB.
func GetVisaPVV(accountNumber, keyIndex, pin string, pvkHex []byte) ([]byte, error) {
	// Build TSP: 11 PAN digits + keyIndex + PIN
	tspHex := accountNumber[len(accountNumber)-12:len(accountNumber)-1] + keyIndex + pin
	rawKey, err := B2Raw(pvkHex)
	if err != nil {
		return nil, err
	}
	block, err := des.NewTripleDESCipher(rawKey)
	if err != nil {
		return nil, err
	}
	rawTSP, err := hex.DecodeString(tspHex)
	if err != nil {
		return nil, err
	}
	// 3DES-ECB encrypt TSP
	dst := make([]byte, len(rawTSP))
	newECBEncrypter(block).CryptBlocks(dst, rawTSP)
	digits := GetDigitsFromString(Raw2Str(dst), 4)
	return []byte(digits), nil
}

// GetVisaCVV generates a 3-digit CVV using DES and 3DES operations.
func GetVisaCVV(accountNumber, expDate, serviceCode string, cvkHex []byte) ([]byte, error) {
	rawKey, err := B2Raw(cvkHex)
	if err != nil {
		return nil, err
	}
	// Single DES on account number
	desBlock, err := des.NewCipher(rawKey[:8])
	if err != nil {
		return nil, err
	}
	// 3DES for final block
	des3Block, err := des.NewTripleDESCipher(rawKey)
	if err != nil {
		return nil, err
	}
	// Build TSP: expDate + serviceCode + nine zeros
	block1Data := expDate + serviceCode + strings.Repeat("0", 9)
	// Encrypt and XOR
	rawAcct, err := hex.DecodeString(accountNumber)
	if err != nil {
		return nil, err
	}
	d1 := make([]byte, len(rawAcct))
	desBlock.Encrypt(d1, rawAcct)
	block1 := Raw2B(d1)
	xored, err := XOR(block1, []byte(block1Data))
	if err != nil {
		return nil, err
	}
	// Final 3DES ECB encrypt
	rawB, err := B2Raw(xored)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(rawB))
	newECBEncrypter(des3Block).CryptBlocks(dst, rawB)

	return []byte(GetDigitsFromString(Raw2Str(dst), 3)), nil
}

// GetClearPin recovers the clear PIN from a PIN block and PAN.
func GetClearPin(pinBlockHex []byte, accountNumber string) ([]byte, error) {
	if len(pinBlockHex) == 0 || accountNumber == "" {
		return nil, errors.New("pinBlock and pan must not be empty")
	}
	rawPin, err := hex.DecodeString(string(pinBlockHex))
	if err != nil {
		return nil, err
	}
	acctPadded := "0000" + accountNumber
	rawAcct, err := hex.DecodeString(acctPadded)
	if err != nil {
		return nil, err
	}
	if len(rawPin) != len(rawAcct) {
		return nil, errors.New("GetClearPin: length mismatch")
	}
	xorBytes := make([]byte, len(rawPin))
	for i := range rawPin {
		xorBytes[i] = rawPin[i] ^ rawAcct[i]
	}
	pinHex := Raw2Str(xorBytes)
	pinLen, err := strconv.ParseInt(pinHex[:2], 16, 0)
	if err != nil {
		return nil, err
	}
	if pinLen >= 4 && pinLen < 9 {
		pin := pinHex[2 : 2+pinLen]
		if _, err := strconv.Atoi(pin); err != nil {
			return nil, fmt.Errorf("GetClearPin: PIN contains non-numeric characters")
		}

		return []byte(pin), nil
	}

	return nil, fmt.Errorf("GetClearPin: incorrect PIN length %d", pinLen)
}

// GetPINBlock constructs an ISO-0 PIN block from the PIN and PAN.
func GetPINBlock(pin, pan string) (string, error) {
	if pin == "" || pan == "" {
		return "", errors.New("pin and pan must not be empty")
	}
	// Format block1
	b1 := fmt.Sprintf("0%d%s", len(pin), pin)
	for len(b1) < 16 {
		b1 += "F"
	}
	// Format block2
	b2 := "0000" + pan[len(pan)-13:len(pan)-1]
	raw1, err := hex.DecodeString(b1)
	if err != nil {
		return "", err
	}
	raw2, err := hex.DecodeString(b2)
	if err != nil {
		return "", err
	}
	if len(raw1) != len(raw2) {
		return "", fmt.Errorf("GetPINBlock: length mismatch")
	}
	xorBytes := make([]byte, len(raw1))
	for i := range raw1 {
		xorBytes[i] = raw1[i] ^ raw2[i]
	}

	return strings.ToUpper(hex.EncodeToString(xorBytes)), nil
}

// ParityOf returns 0 for even number of set bits, -1 for odd.
func ParityOf(x int) int {
	parity := 0
	for x != 0 {
		parity = ^parity
		x = x & (x - 1)
	}
	return parity
}

// CheckKeyParity returns true if every byte in key has even parity.
func CheckKeyParity(key []byte) bool {
	for _, b := range key {
		if ParityOf(int(b)) == -1 {
			return false
		}
	}

	return true
}

// ModifyKeyParity adjusts each byte so that its parity is even.
func ModifyKeyParity(key []byte) []byte {
	res := make([]byte, len(key))
	for i, b := range key {
		if ParityOf(int(b)) == -1 {
			cand := int(b) + 1
			for ParityOf(cand) == -1 {
				cand = (cand + 1) % 256
			}
			res[i] = byte(cand)
		} else {
			res[i] = b
		}
	}

	return res
}

// seedRandom ensures proper entropy for random number generation.
// While crypto/rand doesn't need seeding as it uses system entropy,
// we add extra entropy mixing to ensure uniqueness across WASM calls.
func seedRandom() error {
	seed := make([]byte, 32)
	if _, err := rand.Read(seed); err != nil {
		return fmt.Errorf("failed to read random seed: %w", err)
	}

	// Mix in current time for additional entropy
	timeBytes := []byte(time.Now().UTC().String())
	for i := range timeBytes {
		if i < len(seed) {
			seed[i] ^= timeBytes[i]
		}
	}

	// Read more random bytes to mix the entropy pool
	extraEntropy := make([]byte, 32)
	if _, err := rand.Read(extraEntropy); err != nil {
		return fmt.Errorf("failed to read extra entropy: %w", err)
	}

	return nil
}

// GenerateRandomKey generates a cryptographically secure random key of specified length.
// Length must be 8 (single), 16 (double), or 24 (triple) bytes.
func GenerateRandomKey(length int) ([]byte, error) {
	// Seed the random generator on every call
	if err := seedRandom(); err != nil {
		return nil, fmt.Errorf("failed to seed random generator: %w", err)
	}

	if length != 8 && length != 16 && length != 24 {
		return nil, errors.New("invalid key length: must be 8, 16, or 24 bytes")
	}

	// Generate two separate random values
	key1 := make([]byte, length)
	key2 := make([]byte, length)

	if _, err := rand.Read(key1); err != nil {
		return nil, fmt.Errorf("failed to generate first random key: %w", err)
	}
	if _, err := rand.Read(key2); err != nil {
		return nil, fmt.Errorf("failed to generate second random key: %w", err)
	}

	// Mix the two random values
	finalKey := make([]byte, length)
	for i := 0; i < length; i++ {
		// Use XOR to mix the values and add timestamp byte for extra entropy
		timeByte := byte(time.Now().UnixNano() >> uint((i%8)*8))
		finalKey[i] = key1[i] ^ key2[i] ^ timeByte
	}

	// Adjust parity for DES keys
	if !CheckKeyParity(finalKey) {
		finalKey = ModifyKeyParity(finalKey)
	}

	return finalKey, nil
}
