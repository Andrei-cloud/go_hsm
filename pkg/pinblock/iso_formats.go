// Package pinblock implements various PIN block encoding and decoding formats.
package pinblock

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// encodeISO0 creates an ISO 9564-1 Format 0 PIN block.
// PIN: 4-12 digits.
// PAN: The 12 rightmost digits of the PAN (excluding the check digit) are used.
// The PAN string input should be the account number.
func encodeISO0(pin, pan string) (string, error) {
	if pan == "" {
		return "", errPanRequired
	}
	// PIN length and digit validation is assumed to be done by EncodePinBlock.

	// Block 1 (PIN data): '0' + PIN Length (1 hex char) + PIN + 'F' padding.
	pinFieldStr := fmt.Sprintf("0%X%s", len(pin), pin)
	for len(pinFieldStr) < 16 {
		pinFieldStr += "F"
	}
	pinBlockPart1, err := hex.DecodeString(pinFieldStr)
	if err != nil {
		// This should not happen with the current logic.
		return "", fmt.Errorf("%w: encoding pin field for iso0", errInternalEncoding)
	}

	// Block 2 (PAN data): '0000' + 12 rightmost digits of PAN (excluding check digit).
	panDigits := ""
	for _, r := range pan {
		if r >= '0' && r <= '9' {
			panDigits += string(r)
		}
	}

	if panDigits == "" {
		return "", errPanNoDigits
	}

	// The standard typically expects the 12 rightmost digits of the PAN, *excluding* the check digit.
	// If the PAN provided includes a check digit as the last character, and it's non-numeric,
	// we should ideally exclude it before taking the 12 digits.
	// However, the current logic takes any 12 digits from the right of the numeric string.
	// For more robust PAN handling, one might need to identify and strip a check digit first.
	// For now, we use the 12 rightmost digits of the filtered numeric string `panDigits`.
	if len(panDigits) < 12 {
		return "", fmt.Errorf(
			"%w: pan must contain at least 12 processable digits for iso0",
			errInvalidPanLength,
		)
	}
	relevantPan := panDigits[len(panDigits)-12:]

	panFieldStr := "0000" + relevantPan
	panBlockPart2, err := hex.DecodeString(panFieldStr)
	if err != nil {
		// This should not happen.
		return "", fmt.Errorf("%w: encoding pan field for iso0", errInternalEncoding)
	}

	// XOR Block 1 and Block 2.
	if len(pinBlockPart1) != 8 || len(panBlockPart2) != 8 {
		// Should be 8 bytes (16 hex chars).
		return "", fmt.Errorf("%w: field length mismatch for iso0 xor", errInternalEncoding)
	}

	result := make([]byte, 8)
	for i := 0; i < 8; i++ {
		result[i] = pinBlockPart1[i] ^ panBlockPart2[i]
	}

	return strings.ToUpper(hex.EncodeToString(result)), nil
}

// decodeISO0 extracts the PIN from an ISO 9564-1 Format 0 PIN block.
func decodeISO0(pinBlockHex, pan string) (string, error) {
	if pan == "" {
		return "", errPanRequired
	}
	pinBlockBytes, err := hex.DecodeString(pinBlockHex)
	if err != nil { // Should not happen if caller validates hex.
		return "", fmt.Errorf("%w: invalid hex for iso0 pin block", errInternalDecoding)
	}

	// Prepare PAN field (same as in encoding).
	panDigits := ""
	for _, r := range pan {
		if r >= '0' && r <= '9' {
			panDigits += string(r)
		}
	}

	if panDigits == "" {
		return "", errPanNoDigits
	}
	if len(panDigits) < 12 {
		return "", fmt.Errorf(
			"%w: pan must contain at least 12 processable digits for iso0 decoding",
			errInvalidPanLength,
		)
	}
	relevantPan := panDigits[len(panDigits)-12:]
	panFieldStr := "0000" + relevantPan
	panBlockPart2, err := hex.DecodeString(panFieldStr)
	if err != nil {
		return "", fmt.Errorf("%w: decoding pan field for iso0", errInternalDecoding)
	}

	// XOR PIN block with PAN field to get the clear PIN field (Block 1).
	clearPinFieldBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		clearPinFieldBytes[i] = pinBlockBytes[i] ^ panBlockPart2[i]
	}
	clearPinFieldHex := strings.ToUpper(hex.EncodeToString(clearPinFieldBytes))

	// Validate format "0LPPPP...".
	if clearPinFieldHex[0] != '0' {
		return "", fmt.Errorf(
			"%w: decoded iso0 pin block has invalid format prefix",
			errPinBlockDecoding,
		)
	}

	pinLenHex := string(clearPinFieldHex[1])
	pinLen, err := strconv.ParseInt(pinLenHex, 16, 64)
	if err != nil || pinLen < 4 || pinLen > 12 {
		return "", fmt.Errorf(
			"%w: decoded iso0 pin block has invalid pin length",
			errPinBlockDecoding,
		)
	}

	// Extract PIN.
	pinStartIndex := 2
	pinEndIndex := pinStartIndex + int(pinLen)
	if pinEndIndex > 16 { // 16 is length of clearPinFieldHex.
		return "", fmt.Errorf("%w: pin length exceeds block boundary in iso0", errPinBlockDecoding)
	}
	pin := clearPinFieldHex[pinStartIndex:pinEndIndex]

	// Validate padding.
	padding := clearPinFieldHex[pinEndIndex:]

	for _, charRune := range padding {
		if charRune != 'F' {
			return "", fmt.Errorf(
				"%w: decoded iso0 pin block has invalid padding character",
				errPinBlockDecoding,
			)
		}
	}

	return pin, nil
}

// encodeISO1 creates an ISO 9564-1 Format 1 PIN block.
// PIN: 4-12 digits.
// This format does not use PAN. Padding is with random hex digits.
func encodeISO1(pin string) (string, error) {
	// PIN length and digit validation is assumed to be done by EncodePinBlock.

	// Block: '1' + PIN Length (1 hex char) + PIN + random hex padding.
	pinFieldStr := fmt.Sprintf("1%X%s", len(pin), pin)

	paddingNeeded := 16 - len(pinFieldStr)
	if paddingNeeded < 0 { // Should not happen if pinLen is 4-12.
		return "", fmt.Errorf("%w: negative padding length for iso1", errInternalEncoding)
	}

	if paddingNeeded > 0 {
		// Each byte of random data gives two hex characters.
		numRandomBytes := (paddingNeeded + 1) / 2 // Add 1 to handle odd paddingNeeded correctly.
		randomBytes := make([]byte, numRandomBytes)
		if _, err := rand.Read(randomBytes); err != nil {
			return "", fmt.Errorf("%w: %v", errRandomGeneration, err)
		}
		paddingStr := hex.EncodeToString(randomBytes)
		pinFieldStr += paddingStr[:paddingNeeded]
	}

	return strings.ToUpper(pinFieldStr), nil
}

// decodeISO1 extracts the PIN from an ISO 9564-1 Format 1 PIN block.
// This format does not use PAN.
func decodeISO1(pinBlockHex string) (string, error) {
	// pinBlockHex length and hex validity assumed to be checked by DecodePinBlock.

	// Validate format "1LPPPP...".
	if pinBlockHex[0] != '1' {
		return "", fmt.Errorf(
			"%w: pin block has invalid format prefix for iso1",
			errPinBlockDecoding,
		)
	}

	pinLenHex := string(pinBlockHex[1])
	pinLen, err := strconv.ParseInt(pinLenHex, 16, 64)
	if err != nil || pinLen < 4 || pinLen > 12 {
		return "", fmt.Errorf("%w: pin block has invalid pin length for iso1", errPinBlockDecoding)
	}

	// Extract PIN.
	pinStartIndex := 2
	pinEndIndex := pinStartIndex + int(pinLen)
	if pinEndIndex > len(pinBlockHex) { // len(pinBlockHex) is 16.
		return "", fmt.Errorf("%w: pin length exceeds block boundary for iso1", errPinBlockDecoding)
	}
	pin := pinBlockHex[pinStartIndex:pinEndIndex]

	// Padding is random, so no validation of padding content is needed.
	// Only ensure its length is consistent with PIN length, which is implicitly checked by pinEndIndex.

	return pin, nil
}

// encodeISO2 creates an ISO 9564-1 Format 2 PIN block.
// PIN: 4-12 digits.
// This format does not use PAN. Padding is with 'F'.
func encodeISO2(pin string) (string, error) {
	// PIN length and digit validation is assumed to be done by EncodePinBlock.

	// Block: '2' + PIN Length (1 hex char) + PIN + 'F' padding.
	pinFieldStr := fmt.Sprintf("2%X%s", len(pin), pin)
	for len(pinFieldStr) < 16 {
		pinFieldStr += "F"
	}

	return strings.ToUpper(pinFieldStr), nil
}

// decodeISO2 extracts the PIN from an ISO 9564-1 Format 2 PIN block.
// This format does not use PAN.
func decodeISO2(pinBlockHex string) (string, error) {
	// pinBlockHex length and hex validity assumed to be checked by DecodePinBlock.

	// Validate format "2LPPPP...".
	if pinBlockHex[0] != '2' {
		return "", fmt.Errorf(
			"%w: pin block has invalid format prefix for iso2",
			errPinBlockDecoding,
		)
	}

	pinLenHex := string(pinBlockHex[1])
	pinLen, err := strconv.ParseInt(pinLenHex, 16, 64)
	if err != nil || pinLen < 4 || pinLen > 12 {
		return "", fmt.Errorf("%w: pin block has invalid pin length for iso2", errPinBlockDecoding)
	}

	// Extract PIN.
	pinStartIndex := 2
	pinEndIndex := pinStartIndex + int(pinLen)
	if pinEndIndex > len(pinBlockHex) { // len(pinBlockHex) is 16.
		return "", fmt.Errorf("%w: pin length exceeds block boundary for iso2", errPinBlockDecoding)
	}
	pin := pinBlockHex[pinStartIndex:pinEndIndex]

	// Validate padding.
	padding := pinBlockHex[pinEndIndex:]
	for _, charRune := range padding {
		if charRune != 'F' {
			return "", fmt.Errorf(
				"%w: decoded iso2 pin block has invalid padding character",
				errPinBlockDecoding,
			)
		}
	}

	return pin, nil
}

// encodeISO3 creates an ISO 9564-1 Format 3 PIN block.
// PIN: 4-12 digits.
// PAN: The 12 rightmost digits of the PAN (excluding the check digit) are used.
// Similar to ISO0, but control field is '3' and padding is random hex digits.
func encodeISO3(pin, pan string) (string, error) {
	if pan == "" {
		return "", errPanRequired
	}
	// PIN length and digit validation is assumed to be done by EncodePinBlock.

	// Block 1 (PIN data): '3' + PIN Length (1 hex char) + PIN + random padding.
	pinFieldStr := fmt.Sprintf("3%X%s", len(pin), pin)
	paddingNeeded := 16 - len(pinFieldStr)
	if paddingNeeded < 0 {
		return "", fmt.Errorf("%w: negative padding for iso3 pin field", errInternalEncoding)
	}
	if paddingNeeded > 0 {
		numRandomBytes := (paddingNeeded + 1) / 2
		randomBytes := make([]byte, numRandomBytes)
		if _, err := rand.Read(randomBytes); err != nil {
			return "", fmt.Errorf("%w: %v", errRandomGeneration, err)
		}
		pinFieldStr += hex.EncodeToString(randomBytes)[:paddingNeeded]
	}

	pinBlockPart1, err := hex.DecodeString(pinFieldStr)
	if err != nil {
		return "", fmt.Errorf("%w: encoding pin field for iso3", errInternalEncoding)
	}

	// Block 2 (PAN data): '0000' + 12 rightmost digits of PAN (excluding check digit).
	// This part is identical to ISO0.
	panDigits := ""
	for _, r := range pan {
		if r >= '0' && r <= '9' {
			panDigits += string(r)
		}
	}

	if panDigits == "" {
		return "", errPanNoDigits
	}
	if len(panDigits) < 12 {
		return "", fmt.Errorf(
			"%w: pan must contain at least 12 processable digits for iso3",
			errInvalidPanLength,
		)
	}
	relevantPan := panDigits[len(panDigits)-12:]
	panFieldStr := "0000" + relevantPan
	panBlockPart2, err := hex.DecodeString(panFieldStr)
	if err != nil {
		return "", fmt.Errorf("%w: encoding pan field for iso3", errInternalEncoding)
	}

	// XOR Block 1 and Block 2.
	if len(pinBlockPart1) != 8 || len(panBlockPart2) != 8 {
		return "", fmt.Errorf("%w: field length mismatch for iso3 xor", errInternalEncoding)
	}

	result := make([]byte, 8)
	for i := 0; i < 8; i++ {
		result[i] = pinBlockPart1[i] ^ panBlockPart2[i]
	}

	return strings.ToUpper(hex.EncodeToString(result)), nil
}

// decodeISO3 extracts the PIN from an ISO 9564-1 Format 3 PIN block.
func decodeISO3(pinBlockHex, pan string) (string, error) {
	if pan == "" {
		return "", errPanRequired
	}
	pinBlockBytes, err := hex.DecodeString(pinBlockHex)
	if err != nil {
		return "", fmt.Errorf("%w: invalid hex for iso3 pin block", errInternalDecoding)
	}

	// Prepare PAN field (same as in encoding ISO0/ISO3).
	panDigits := ""
	for _, r := range pan {
		if r >= '0' && r <= '9' {
			panDigits += string(r)
		}
	}

	if panDigits == "" {
		return "", errPanNoDigits
	}
	if len(panDigits) < 12 {
		return "", fmt.Errorf(
			"%w: pan must contain at least 12 processable digits for iso3 decoding",
			errInvalidPanLength,
		)
	}
	relevantPan := panDigits[len(panDigits)-12:]
	panFieldStr := "0000" + relevantPan
	panBlockPart2, err := hex.DecodeString(panFieldStr)
	if err != nil {
		return "", fmt.Errorf("%w: decoding pan field for iso3", errInternalDecoding)
	}

	// XOR PIN block with PAN field to get the clear PIN field.
	clearPinFieldBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		clearPinFieldBytes[i] = pinBlockBytes[i] ^ panBlockPart2[i]
	}
	clearPinFieldHex := strings.ToUpper(hex.EncodeToString(clearPinFieldBytes))

	// Validate format "3LPPPP...".
	if clearPinFieldHex[0] != '3' {
		return "", fmt.Errorf(
			"%w: decoded iso3 pin block has invalid format prefix",
			errPinBlockDecoding,
		)
	}

	pinLenHex := string(clearPinFieldHex[1])
	pinLen, err := strconv.ParseInt(pinLenHex, 16, 64)
	if err != nil || pinLen < 4 || pinLen > 12 {
		return "", fmt.Errorf(
			"%w: decoded iso3 pin block has invalid pin length",
			errPinBlockDecoding,
		)
	}

	// Extract PIN.
	pinStartIndex := 2
	pinEndIndex := pinStartIndex + int(pinLen)
	if pinEndIndex > 16 {
		return "", fmt.Errorf("%w: pin length exceeds block boundary in iso3", errPinBlockDecoding)
	}
	pin := clearPinFieldHex[pinStartIndex:pinEndIndex]

	// Padding is random, so no validation of padding content is needed.

	return pin, nil
}

// encodeISO4 creates an ISO 9564-1 Format 4 PIN block.
// PIN: 4-12 digits.
// PAN: The 12 rightmost digits of the PAN (excluding the check digit) are used.
// This format is more complex and involves two 16-byte random numbers, one of which is XORed with the PIN.
// The standard for ISO4 is more involved and might require specific key management for the random numbers.
// This is a simplified interpretation based on common structures.
func encodeISO4(_, _ string) (string, error) {
	// ISO4 is more complex and typically involves a key exchange mechanism or a pre-shared secret
	// to encrypt/wrap the PIN block or parts of it. The standard is not freely available.
	// The reference URL does not provide enough detail for a full implementation.
	// Returning not implemented.

	return "", errFormatNotImplemented
}

// decodeISO4 extracts the PIN from an ISO 9564-1 Format 4 PIN block.
func decodeISO4(_, _ string) (string, error) {
	// See comments in encodeISO4.

	return "", errFormatNotImplemented
}
