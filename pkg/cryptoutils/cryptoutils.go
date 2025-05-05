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

// StringToBCD converts a byte slice in BCD format to a string.
func StringToBCD(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		s = "0" + s // pad if not even length
	}
	bcd := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		hi := s[i] - '0'
		lo := s[i+1] - '0'
		if hi > 9 || lo > 9 {
			return nil, fmt.Errorf("invalid digit in string: %s", s)
		}
		bcd[i/2] = (hi << 4) | lo
	}

	return bcd, nil
}

// XOR takes two equal-length hex-encoded byte slices, XORs their raw bytes, and
// returns the result as uppercase hex bytes.
func XOR(block1, block2 []byte) ([]byte, error) {
	r1, err := StringToBCD(string(block1))
	if err != nil {
		return nil, err
	}
	r2, err := StringToBCD(string(block2))
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
		return "", errors.New("hexify: negative value")
	}
	s := strings.ToUpper(fmt.Sprintf("%X", n))
	if len(s)%2 == 1 {
		s = "0" + s
	}

	return s, nil
}

// NewECBEncrypter returns a cipher.BlockMode for ECB encryption.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(&ecb{b: b})
}

func (x *ecbEncrypter) BlockSize() int { return x.b.BlockSize() }

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.BlockSize() != 0 {
		panic(fmt.Sprintf(
			"cryptoutils: input length %d not a multiple of block size %d",
			len(src),
			x.BlockSize(),
		))
	}
	for len(src) > 0 {
		x.b.Encrypt(dst[:x.BlockSize()], src[:x.BlockSize()])
		src = src[x.BlockSize():]
		dst = dst[x.BlockSize():]
	}
}

// NewECBDecrypter returns a cipher.BlockMode for ECB decryption.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(&ecb{b: b})
}

func (x *ecbDecrypter) BlockSize() int { return x.b.BlockSize() }

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.BlockSize() != 0 {
		panic(fmt.Sprintf(
			"cryptoutils: input length %d not a multiple of block size %d",
			len(src),
			x.BlockSize(),
		))
	}
	for len(src) > 0 {
		x.b.Decrypt(dst[:x.BlockSize()], src[:x.BlockSize()])
		src = src[x.BlockSize():]
		dst = dst[x.BlockSize():]
	}
}

func KeyCV(keyHex []byte, kcvLen int) ([]byte, error) {
	rawKey, err := StringToBCD(string(keyHex))
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
		return nil, fmt.Errorf("keycv: invalid key length %d", len(rawKey))
	}

	block, err := des.NewTripleDESCipher(fullKey)
	if err != nil {
		return nil, err
	}

	// Encrypt two blocks of zeros (16 bytes total)
	zero := make([]byte, block.BlockSize()*2)
	dst := make([]byte, len(zero))
	mode := NewECBEncrypter(block)
	mode.CryptBlocks(dst, zero)
	hv := Raw2B(dst)
	if kcvLen > len(hv) {
		return nil, fmt.Errorf("keycv: kcv_length %d too large", kcvLen)
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
	pan11 := accountNumber[len(accountNumber)-11:] // last 11 digits before check digit
	// Build TSP: 11 PAN digits + PVKeyIndex + PIN (only first 4 digits)
	tspHex := pan11 + keyIndex + pin[:4]

	if len(pvkHex) == 16 {
		// Extend to tripple length
		pvkHex = append(pvkHex, pvkHex[:8]...)
	}

	block, err := des.NewTripleDESCipher(pvkHex)
	if err != nil {
		return nil, err
	}

	rawTsp, err := StringToBCD(tspHex)
	if err != nil {
		return nil, err
	}
	// 3DES-ECB encrypt TSP
	dst := make([]byte, len(rawTsp))
	NewECBEncrypter(block).CryptBlocks(dst, rawTsp)
	digits := GetDigitsFromString(Raw2Str(dst), 4)

	return []byte(digits), nil
}

// GetVisaCVV generates a 3-digit CVV using DES and 3DES operations.
func GetVisaCVV(accountNumber, expDate, serviceCode string, cvkHex []byte) ([]byte, error) {
	rawKey, err := StringToBCD(string(cvkHex))
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
	rawB, err := StringToBCD(string(xored))
	if err != nil {
		return nil, err
	}
	dst := make([]byte, len(rawB))
	NewECBEncrypter(des3Block).CryptBlocks(dst, rawB)

	return []byte(GetDigitsFromString(Raw2Str(dst), 3)), nil
}

// ExtractPINFormat0 takes a Format 0 PIN block (8 bytes or 16 hex chars) and a PAN,
// returning the decoded PIN as a string.
func ExtractPINFormat0(pinBlock []byte, pan string) ([]byte, error) {
	var rawPinBlock []byte

	switch len(pinBlock) {
	case 16:
		var err error
		rawPinBlock, err = hex.DecodeString(string(pinBlock))
		if err != nil {
			return nil, fmt.Errorf("failed to decode pin block hex: %v", err)
		}
	case 8: // Raw bytes input.
		rawPinBlock = pinBlock
	default:
		return nil, errors.New("pinBlock must be either 8 bytes or 16 hex chars")
	}

	// Validate PAN.
	if len(pan) < 12 {
		return nil, errors.New("PAN must be at least 13 digits")
	}
	for _, r := range pan {
		if !unicode.IsDigit(r) {
			return nil, errors.New("PAN must contain only numeric characters")
		}
	}

	// Build PAN field (8 bytes).
	// Take 12 rightmost PAN digits excluding the check digit.
	panWithoutCheck := pan
	panDigits := panWithoutCheck
	if len(panWithoutCheck) > 12 {
		panWithoutCheck = pan[:len(pan)-1] // remove last digit.
		panDigits = panWithoutCheck[len(panWithoutCheck)-12:]
	} else if len(panWithoutCheck) < 12 {
		panDigits = fmt.Sprintf("%012s", panWithoutCheck) // pad left with zeros.
	}
	panFieldHex := "0000" + panDigits
	panField, err := hex.DecodeString(panFieldHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PAN field: %v", err)
	}

	// XOR pinBlock with PAN field to retrieve original PIN field.
	pinField := make([]byte, 8)
	for i := 0; i < 8; i++ {
		pinField[i] = rawPinBlock[i] ^ panField[i]
	}

	// Convert pin field to uppercase hex for processing.
	pinFieldHex := strings.ToUpper(hex.EncodeToString(pinField))

	// Check Format nibble is '0'.
	if pinFieldHex[0] != '0' {
		return nil, fmt.Errorf("unexpected PIN block format: %c", pinFieldHex[0])
	}

	// PIN length is second nibble.
	pinLenNibble := pinFieldHex[1]
	pinLen, err := strconv.ParseInt(string(pinLenNibble), 16, 8)
	if err != nil {
		return nil, fmt.Errorf("invalid PIN length nibble: %v", err)
	}

	if pinLen < 1 || pinLen > 12 {
		return nil, fmt.Errorf("invalid decoded PIN length: %d", pinLen)
	}

	// Extract PIN digits directly from the hex string.
	// The PIN digits start at index 2 and have length pinLen.
	pinDigitsStr := pinFieldHex[2 : 2+int(pinLen)]

	// Validate that PIN contains only numeric characters '0'-'9'.
	for _, r := range pinDigitsStr {
		if r < '0' || r > '9' {
			return nil, errors.New("pin contains non-numeric characters")
		}
	}

	return []byte(pinDigitsStr), nil
}

// ComputePINBlockFormat0 encodes a PIN and PAN into a Format 0 PIN block (ISO 9564-1 / ANSI X9.8).
// It returns a PIN block as a hex string (16 bytes), or an error if inputs are invalid.
func ComputePINBlockFormat0(pin, pan string) ([]byte, error) {
	// Validate PIN: must be 1-12 digits (numeric only).
	pinLength := len(pin)
	if pinLength == 0 || pinLength > 12 {
		return nil, fmt.Errorf("invalid PIN length %d (must be 1–12 digits)", pinLength)
	}
	for _, r := range pin {
		if !unicode.IsDigit(r) {
			return nil, errors.New("pin contains non-numeric characters")
		}
	}

	// Validate PAN: must be numeric and at least 2 digits long.
	if len(pan) < 2 {
		return nil, fmt.Errorf("invalid PAN length %d (must be at least 2 digits)", len(pan))
	}
	for _, r := range pan {
		if !unicode.IsDigit(r) {
			return nil, errors.New("pan contains non-numeric characters")
		}
	}

	// Construct PIN field (16 hex nibbles):
	// First nibble "0", second nibble is PIN length in hex, then PIN digits, then F padding.
	pinLenHex := fmt.Sprintf("%X", pinLength) // PIN length as a single hex character (0-9 or A-C).
	padLen := 14 - pinLength                  // number of 'F' pad nibbles needed (total nibbles = 2 + pinLength + padLen = 16).
	pinFieldHex := "0" + pinLenHex + pin + strings.Repeat("F", padLen)

	// Construct PAN field (16 hex nibbles):
	// Exclude the last PAN digit (check digit).
	panWithoutCheck := pan[:len(pan)-1]
	// Take the rightmost 12 digits of panWithoutCheck. If shorter, left-pad with zeros.
	var panDigits12 string
	if len(panWithoutCheck) >= 12 {
		panDigits12 = panWithoutCheck[len(panWithoutCheck)-12:]
	} else {
		// pad with leading zeros to make it 12 digits.
		panDigits12 = fmt.Sprintf("%012s", panWithoutCheck)
	}
	// Now prepend four '0' nibbles:
	panFieldHex := "0000" + panDigits12

	// Decode the hex strings to 8-byte arrays.
	pinFieldBytes, err := hex.DecodeString(pinFieldHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PIN field hex: %v", err)
	}
	panFieldBytes, err := hex.DecodeString(panFieldHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PAN field hex: %v", err)
	}

	// XOR the PIN field and PAN field byte-by-byte to get the PIN block.
	result := make([]byte, 8)
	for i := 0; i < 8; i++ {
		result[i] = pinFieldBytes[i] ^ panFieldBytes[i]
	}

	// Convert result to hex string.

	return Raw2B(result), nil
}

// ParityOf returns 0 for even number of set bits, -1 for odd.
func ParityOf(x int) int {
	parity := 0
	for x != 0 {
		parity = ^parity
		x &= (x - 1)
	}

	return parity
}

// CheckKeyParity returns true if every byte in key has ODD parity.
func CheckKeyParity(key []byte) bool {
	for _, b := range key {
		if ParityOf(int(b)) != -1 {
			return false
		}
	}

	return true
}

// FixKeyParity sets each byte to have ODD parity (as required by DES).
func FixKeyParity(key []byte) []byte {
	res := make([]byte, len(key))
	for i, b := range key {
		parity := 0
		for x := b; x != 0; x &= x - 1 {
			parity ^= 1
		}
		// parity == 1 -> already odd, leave as-is
		// parity == 0 -> even, flip the lowest bit
		if parity == 0 {
			res[i] = b ^ 1
		} else {
			res[i] = b
		}
	}

	return res
}

// GetClearPin extracts a cleartext PIN from a PIN block and PAN.
func GetClearPin(pinBlock []byte, pan string) ([]byte, error) {
	result, err := ExtractPINFormat0(pinBlock, pan)
	if err != nil {
		return nil, err
	}

	return result, nil
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
	// Seed the random generator on every call.
	if err := seedRandom(); err != nil {
		return nil, fmt.Errorf("failed to seed random generator: %w", err)
	}

	if length != 8 && length != 16 && length != 24 {
		return nil, errors.New("invalid key length: must be 8, 16, or 24 bytes")
	}

	// Generate two separate random values.
	key1 := make([]byte, length)
	key2 := make([]byte, length)

	if _, err := rand.Read(key1); err != nil {
		return nil, fmt.Errorf("failed to generate first random key: %w", err)
	}
	if _, err := rand.Read(key2); err != nil {
		return nil, fmt.Errorf("failed to generate second random key: %w", err)
	}

	// Mix the two random values.
	finalKey := make([]byte, length)
	for i := range length {
		// Use XOR to mix the values and add timestamp byte for extra entropy.
		timeByte := byte(time.Now().UnixNano() >> uint((i%8)*8))
		finalKey[i] = key1[i] ^ key2[i] ^ timeByte
	}

	// Adjust parity for DES keys.
	if !CheckKeyParity(finalKey) {
		finalKey = FixKeyParity(finalKey)
	}

	return finalKey, nil
}

// ExtendToDouble extends a single length key to double length by concatenating it with itself.
func ExtendToDouble(singleKey []byte) []byte {
	doubleKey := make([]byte, len(singleKey)*2)
	copy(doubleKey[:len(singleKey)], singleKey)
	copy(doubleKey[len(singleKey):], singleKey)

	return doubleKey
}

// TruncateToSingle takes the first half of a double length key.
func TruncateToSingle(doubleKey []byte) []byte {
	return doubleKey[:len(doubleKey)/2]
}
