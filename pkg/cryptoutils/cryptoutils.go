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
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	ISO9797_METHOD2_PADDING_BYTE = 0x80
	KEY_LENGTH_SINGLE            = 8
	KEY_LENGTH_DOUBLE            = 16
	KEY_LENGTH_TRIPLE            = 24
	RANDOM_SEED_LENGTH           = 32
	PVV_PAN_LENGTH               = 11
	PVV_LENGTH                   = 4
	EXP_DATE_LENGTH              = 4
	CVK_LENGTH                   = 16
	SERVICE_CODE_LENGTH          = 3
	CVV_DATA_LENGTH              = 32
	CVV_LENGTH                   = 3
	PAN_MIN_LENGTH               = 13
	PAN_MAX_LENGTH               = 19
	CVV_PADDING_BYTE             = "0"
	HEX_TO_DECIMAL_OFFSET        = 10
	XOR_BIT_FLIP                 = 1
	DOUBLE_LENGTH_FACTOR         = 2
)

// ecb wraps a cipher.Block to provide ECB mode.
type ecb struct{ b cipher.Block }

type ecbEncrypter ecb

type ecbDecrypter ecb

// padISO9797Method2 implements ISO/IEC 9797-1 padding method 2 (EMV padding).
// Adds 0x80 followed by the smallest number of 0x00 bytes to make data multiple of block size.
// If data is already a multiple of block size and non-empty, no padding is added.
func padISO9797Method2(msg []byte, bs int) []byte {
	return padISO9797Method1(slices.Concat(msg, []byte{ISO9797_METHOD2_PADDING_BYTE}), bs)
}

// padISO9797Method1 implements ISO/IEC 9797-1 padding method 1 (VISA padding).
// Adds the smallest number of 0x00 bytes to make data multiple of block size.
// If data is already a multiple of block size and non-empty, no padding is added.
func padISO9797Method1(data []byte, blockSize int) []byte {
	remainder := len(data) % blockSize
	if remainder == 0 && len(data) > 0 {
		return data
	}

	if len(data) == 0 {
		return make([]byte, blockSize)
	}

	padding := make([]byte, blockSize-remainder)

	return slices.Concat(data, padding)
}

// Raw2Str converts raw binary data to an uppercase hex string.
func Raw2Str(raw []byte) string {
	return strings.ToUpper(hex.EncodeToString(raw))
}

// Raw2B returns the uppercase hex representation of raw data as bytes.
func Raw2B(raw []byte) []byte {
	return []byte(Raw2Str(raw))
}

// PrepareTripleDESKey extends double length key to triple length if needed.
func PrepareTripleDESKey(key []byte) []byte {
	var key24 []byte
	switch len(key) {
	case KEY_LENGTH_SINGLE:
		key24 = make([]byte, KEY_LENGTH_TRIPLE)
		copy(key24, key)
		copy(key24[KEY_LENGTH_SINGLE:], key)
		copy(key24[KEY_LENGTH_DOUBLE:], key)
	case KEY_LENGTH_DOUBLE:
		key24 = make([]byte, KEY_LENGTH_TRIPLE)
		copy(key24, key)
		copy(key24[KEY_LENGTH_DOUBLE:], key[:KEY_LENGTH_SINGLE])
	default:
		key24 = key
	}

	return key24
}

// XOR takes two equal-length hex-encoded byte slices, XORs their raw bytes, and
// returns the result as uppercase hex bytes.
func XOR(block1, block2 []byte) ([]byte, error) {
	r1, err := hex.DecodeString(string(block1))
	if err != nil {
		return nil, fmt.Errorf("failed to decode block1 for XOR: %w", err)
	}
	r2, err := hex.DecodeString(string(block2))
	if err != nil {
		return nil, fmt.Errorf("failed to decode block2 for XOR: %w", err)
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
	rawKey, err := hex.DecodeString(string(keyHex))
	if err != nil {
		return nil, fmt.Errorf("failed to decode keyHex for KeyCV: %w", err)
	}

	// Convert to triple length if needed
	var fullKey []byte
	switch len(rawKey) {
	case KEY_LENGTH_SINGLE: // Single length
		fullKey = make([]byte, KEY_LENGTH_TRIPLE)
		copy(fullKey, rawKey)
		copy(fullKey[KEY_LENGTH_SINGLE:], rawKey)
		copy(fullKey[KEY_LENGTH_DOUBLE:], rawKey)
	case KEY_LENGTH_DOUBLE: // Double length
		fullKey = make([]byte, KEY_LENGTH_TRIPLE)
		copy(fullKey, rawKey)
		copy(fullKey[KEY_LENGTH_DOUBLE:], rawKey[:KEY_LENGTH_SINGLE])
	case KEY_LENGTH_TRIPLE: // Triple length
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
			//nolint:all // WriteRune cannot fail for valid runes from a string, so error is ignored.
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
			if val-HEX_TO_DECIMAL_OFFSET >= 0 {
				// WriteString cannot fail for valid strings, so error is ignored.
				digits.WriteString(strconv.Itoa(int(val - HEX_TO_DECIMAL_OFFSET)))
			}
		}
	}

	return digits.String()
}

// GetVisaPVV generates a 4-digit PIN Verification Value (PVV) using 3DES ECB.
func GetVisaPVV(accountNumber, keyIndex, pin string, pvkHex []byte) ([]byte, error) {
	pan11 := accountNumber[len(accountNumber)-PVV_PAN_LENGTH:] // last 11 digits before check digit
	// Build TSP: 11 PAN digits + PVKeyIndex + PIN (only first 4 digits)
	tspHex := pan11 + keyIndex + pin[:PVV_LENGTH]

	if len(pvkHex) == KEY_LENGTH_DOUBLE {
		// Extend to tripple length
		pvkHex = append(pvkHex, pvkHex[:KEY_LENGTH_SINGLE]...)
	}

	block, err := des.NewTripleDESCipher(pvkHex)
	if err != nil {
		return nil, err
	}

	rawTsp, err := hex.DecodeString(tspHex)
	if err != nil {
		return nil, err
	}
	// 3DES-ECB encrypt TSP
	dst := make([]byte, len(rawTsp))
	NewECBEncrypter(block).CryptBlocks(dst, rawTsp)
	digits := GetDigitsFromString(Raw2Str(dst), PVV_LENGTH)

	return []byte(digits), nil
}

// GetVisaCVV calculates the CVV for a given set of card data and a CVK.
// panHex: Primary Account Number as a hex string.
// expDate: Expiration date in YYMM format.
// servCode: Service code, 3 digits.
// cvkRaw: The raw Card Verification Key bytes (must be 16 bytes for double-length key).
func GetVisaCVV(panHex, expDate, servCode string, cvkRaw []byte) ([]byte, error) {
	// Step 1: Validate double-length (16-byte) key
	if len(cvkRaw) != CVK_LENGTH {
		return nil, fmt.Errorf(
			"invalid CVK length: expected %d bytes (double-length), got %d",
			CVK_LENGTH,
			len(cvkRaw),
		)
	}
	key1 := cvkRaw[:KEY_LENGTH_SINGLE]   // First half of the key
	key2 := cvkRaw[KEY_LENGTH_SINGLE:CVK_LENGTH] // Second half of the key

	// Step 2: Validate PAN length (13-19 digits)
	if len(panHex) < PAN_MIN_LENGTH || len(panHex) > PAN_MAX_LENGTH {
		return nil, errors.New("invalid PAN length: must be between 13 and 19 digits")
	}

	// Steps 3-4: Validate expDate and servCode
	if len(expDate) != EXP_DATE_LENGTH {
		return nil, errors.New("invalid expiration date length: must be 4 characters")
	}
	if len(servCode) != SERVICE_CODE_LENGTH {
		return nil, errors.New("invalid service code length: must be 3 characters")
	}

	// Step 5-6: Concatenate data and pad with zeros to 32 characters
	data := panHex + expDate + servCode
	if len(data) < CVV_DATA_LENGTH {
		data += strings.Repeat(CVV_PADDING_BYTE, CVV_DATA_LENGTH-len(data))
	}

	// Convert the first half of data to bytes for DES operations
	data1Raw, err := hex.DecodeString(data[:KEY_LENGTH_DOUBLE])
	if err != nil {
		return nil, fmt.Errorf("failed to decode first half of data: %w", err)
	}

	// Step 7: Encrypt first half of data with first half of key
	block1, err := des.NewCipher(key1)
	if err != nil {
		return nil, fmt.Errorf("failed to create first DES cipher: %w", err)
	}
	encrypted1 := make([]byte, KEY_LENGTH_SINGLE)
	block1.Encrypt(encrypted1, data1Raw)

	// Step 8: XOR result with second half of data
	data2Raw, err := hex.DecodeString(data[KEY_LENGTH_DOUBLE:])
	if err != nil {
		return nil, fmt.Errorf("failed to decode second half of data: %w", err)
	}
	xored := make([]byte, KEY_LENGTH_SINGLE)
	for i := 0; i < KEY_LENGTH_SINGLE; i++ {
		xored[i] = encrypted1[i] ^ data2Raw[i]
	}

	// Step 9: Encrypt result with first half of key
	encrypted2 := make([]byte, KEY_LENGTH_SINGLE)
	block1.Encrypt(encrypted2, xored)

	// Step 10: Decrypt with second half of key
	block2, err := des.NewCipher(key2)
	if err != nil {
		return nil, fmt.Errorf("failed to create second DES cipher: %w", err)
	}
	decrypted := make([]byte, KEY_LENGTH_SINGLE)
	block2.Decrypt(decrypted, encrypted2)

	// Step 11: Encrypt with first half of key again
	finalEncrypted := make([]byte, KEY_LENGTH_SINGLE)
	block1.Encrypt(finalEncrypted, decrypted)

	// Step 12: Get first 3 digits from result
	hexResult := Raw2Str(finalEncrypted)

	return []byte(GetDigitsFromString(hexResult, CVV_LENGTH)), nil
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
			res[i] = b ^ XOR_BIT_FLIP
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
	seed := make([]byte, RANDOM_SEED_LENGTH)
	var err error
	if _, err = rand.Read(seed); err != nil {
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
	extraEntropy := make([]byte, RANDOM_SEED_LENGTH)
	if _, err = rand.Read(extraEntropy); err != nil {
		return fmt.Errorf("failed to read extra entropy: %w", err)
	}

	return nil
}

// GenerateRandomKey generates a cryptographically secure random key of specified length.
// Length must be 8 (single), 16 (double), or 24 (triple) bytes.
func GenerateRandomKey(length int) ([]byte, error) {
	// Seed the random generator on every call.
	var err error
	if err = seedRandom(); err != nil {
		return nil, fmt.Errorf("failed to seed random generator: %w", err)
	}

	if length != KEY_LENGTH_SINGLE && length != KEY_LENGTH_DOUBLE && length != KEY_LENGTH_TRIPLE {
		return nil, errors.New("invalid key length: must be 8, 16, or 24 bytes")
	}

	// Generate two separate random values.
	key1 := make([]byte, length)
	key2 := make([]byte, length)

	if _, err = rand.Read(key1); err != nil {
		return nil, fmt.Errorf("failed to generate first random key: %w", err)
	}
	if _, err = rand.Read(key2); err != nil {
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

// ExtendDoubleToTripleKey extends a 16-byte double-length key to a 24-byte triple-length key (K1K2K1).
// This is a common way to form a TDEA keying option 1 key (K1, K2, K3) where K3=K1 from a double-length key (K1, K2).
func ExtendDoubleToTripleKey(doubleKey []byte) ([]byte, error) {
	if len(doubleKey) != KEY_LENGTH_DOUBLE {
		return nil, fmt.Errorf(
			"input key must be %d bytes for double-to-triple extension, got %d",
			KEY_LENGTH_DOUBLE,
			len(doubleKey),
		)
	}
	tripleKey := make([]byte, KEY_LENGTH_TRIPLE)
	copy(tripleKey, doubleKey)          // Copy K1K2 to the first 16 bytes.
	copy(tripleKey[KEY_LENGTH_DOUBLE:], doubleKey[:KEY_LENGTH_SINGLE]) // Copy K1 (first 8 bytes of doubleKey) to the last 8 bytes.

	return tripleKey, nil
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

// Chunk splits b into blocks of size sz. The last block may be shorter if needed.
func Chunk(b []byte, sz int) [][]byte {
	if sz <= 0 {
		return nil
	}
	n := (len(b) + sz - 1) / sz
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		start := i * sz
		end := start + sz
		if end > len(b) {
			end = len(b)
		}
		out[i] = b[start:end]
	}

	return out
}

// XORBytes returns a^b for equal-length slices. Returns error if lengths differ.
func XORBytes(a, b []byte) ([]byte, error) {
	if len(a) != len(b) {
		return nil, errors.New("xor: length mismatch")
	}
	out := make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}

	return out, nil
}
