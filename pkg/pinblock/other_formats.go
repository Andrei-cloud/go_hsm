// Package pinblock implements various PIN block encoding and decoding formats.
package pinblock

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// ANSI X9.8 (also known as Format 0 or ECI-2 or DIEBOLD-0).
// PIN: 4-14 digits.
// PAN: The 12 rightmost digits of the PAN (excluding the check digit) are used.
func encodeANSIX98(pin, pan string) (string, error) {
	if pan == "" {
		return "", errPanRequired
	}

	// PIN length and digit validation is assumed to be done by EncodePinBlock.

	// Block 1 (PIN data): PIN Length (1 hex char, 4-14 -> 0x4-0xE) + PIN + 'F' padding.
	// Note: ANSI X9.8 specifies PIN length from 4 to 14.
	pinFieldStr := fmt.Sprintf("%X%s", len(pin), pin)
	for len(pinFieldStr) < 16 {
		pinFieldStr += "F"
	}
	pinBlockPart1, err := hex.DecodeString(pinFieldStr)
	if err != nil {
		return "", fmt.Errorf("%w: encoding pin field for ansi x9.8", errInternalEncoding)
	}

	// Block 2 (PAN data): '0000' + 12 rightmost digits of PAN (excluding check digit).
	panOnlyDigits := ""
	for _, r := range pan {
		if r >= '0' && r <= '9' {
			panOnlyDigits += string(r)
		}
	}

	if panOnlyDigits == "" {
		return "", errPanNoDigits
	}

	// The standard typically expects the 12 rightmost digits of the PAN, *excluding* the check digit.
	if len(panOnlyDigits) < 12 { // Must have at least 11 digits for PAN part + 1 check digit.
		return "", fmt.Errorf(
			"%w: pan must contain at least 12 processable digits for ansi x9.8",
			errInvalidPanLength,
		)
	}
	relevantPan := panOnlyDigits[len(panOnlyDigits)-12:]

	panFieldStr := "0000" + relevantPan
	panBlockPart2, err := hex.DecodeString(panFieldStr)
	if err != nil {
		return "", fmt.Errorf("%w: encoding pan field for ansi x9.8", errInternalEncoding)
	}

	// XOR Block 1 and Block 2.
	if len(pinBlockPart1) != 8 || len(panBlockPart2) != 8 {
		return "", fmt.Errorf("%w: field length mismatch for ansi x9.8 xor", errInternalEncoding)
	}

	result := make([]byte, 8)
	for i := 0; i < 8; i++ {
		result[i] = pinBlockPart1[i] ^ panBlockPart2[i]
	}

	return strings.ToUpper(hex.EncodeToString(result)), nil
}

func decodeANSIX98(pinBlockHex, pan string) (string, error) {
	if pan == "" {
		return "", errPanRequired
	}
	pinBlockBytes, err := hex.DecodeString(pinBlockHex)
	if err != nil {
		return "", fmt.Errorf("%w: invalid hex for ansi x9.8 pin block", errInternalDecoding)
	}

	// Prepare PAN field (same as in encoding).
	panOnlyDigits := ""
	for _, r := range pan {
		if r >= '0' && r <= '9' {
			panOnlyDigits += string(r)
		}
	}

	if panOnlyDigits == "" {
		return "", errPanNoDigits
	}
	if len(panOnlyDigits) < 12 {
		return "", fmt.Errorf(
			"%w: pan must contain at least 12 processable digits for ansi x9.8 decoding",
			errInvalidPanLength,
		)
	}
	relevantPan := panOnlyDigits[len(panOnlyDigits)-12:]
	panFieldStr := "0000" + relevantPan
	panBlockPart2, err := hex.DecodeString(panFieldStr)
	if err != nil {
		return "", fmt.Errorf("%w: decoding pan field for ansi x9.8", errInternalDecoding)
	}

	// XOR PIN block with PAN field to get the clear PIN field.
	clearPinFieldBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		clearPinFieldBytes[i] = pinBlockBytes[i] ^ panBlockPart2[i]
	}
	clearPinFieldHex := strings.ToUpper(hex.EncodeToString(clearPinFieldBytes))

	// Validate format "LPPPP...". L is PIN length (0x4-0xE).
	pinLenHex := string(clearPinFieldHex[0])
	pinLen, err := strconv.ParseInt(pinLenHex, 16, 64)
	if err != nil || pinLen < 4 || pinLen > 14 { // ANSI X9.8 PIN length 4-14.
		return "", fmt.Errorf(
			"%w: decoded ansi x9.8 pin block has invalid pin length",
			errPinBlockDecoding,
		)
	}

	// Extract PIN.
	pinStartIndex := 1 // PIN starts after the length character.
	pinEndIndex := pinStartIndex + int(pinLen)
	if pinEndIndex > 16 { // 16 is length of clearPinFieldHex.
		return "", fmt.Errorf(
			"%w: pin length exceeds block boundary in ansi x9.8",
			errPinBlockDecoding,
		)
	}
	pin := clearPinFieldHex[pinStartIndex:pinEndIndex]

	// Validate padding.
	padding := clearPinFieldHex[pinEndIndex:]
	for _, charRune := range padding {
		if charRune != 'F' {
			return "", fmt.Errorf(
				"%w: decoded ansi x9.8 pin block has invalid padding character",
				errPinBlockDecoding,
			)
		}
	}

	return pin, nil
}

// VISA1.
// PIN: 4-12 digits.
// PAN: The 11 rightmost digits of the PAN (excluding the check digit) are used.
// The 12th digit is the check digit of the PAN.
func encodeVISA1(pin, pan string) (string, error) {
	if pan == "" {
		return "", errPanRequired
	}

	// PIN length and digit validation is assumed to be done by EncodePinBlock.

	// Block 1 (PIN data): PIN Length (1 hex char) + PIN + 'F' padding.
	pinFieldStr := fmt.Sprintf("%X%s", len(pin), pin)
	for len(pinFieldStr) < 16 {
		pinFieldStr += "F"
	}
	pinBlockPart1, err := hex.DecodeString(pinFieldStr)
	if err != nil {
		return "", fmt.Errorf("%w: encoding pin field for visa1", errInternalEncoding)
	}

	// Block 2 (PAN data): '0000' + 11 rightmost digits of PAN (excluding check digit) + check digit.
	panOnlyDigits := ""
	for _, r := range pan {
		if r >= '0' && r <= '9' {
			panOnlyDigits += string(r)
		}
	}

	if panOnlyDigits == "" {
		return "", errPanNoDigits
	}

	if len(panOnlyDigits) < 12 { // Must have at least 11 digits for PAN part + 1 check digit.
		return "", fmt.Errorf(
			"%w: pan must contain at least 12 processable digits for visa1",
			errInvalidPanLength,
		)
	}
	// For VISA1, it's the 11 rightmost digits of the PAN (excluding the check digit) and the check digit itself.
	// So, we take the last 12 digits of the numeric PAN string.
	relevantPan := panOnlyDigits[len(panOnlyDigits)-12:]

	panFieldStr := "0000" + relevantPan
	panBlockPart2, err := hex.DecodeString(panFieldStr)
	if err != nil {
		return "", fmt.Errorf("%w: encoding pan field for visa1", errInternalEncoding)
	}

	// XOR Block 1 and Block 2.
	if len(pinBlockPart1) != 8 || len(panBlockPart2) != 8 {
		return "", fmt.Errorf("%w: field length mismatch for visa1 xor", errInternalEncoding)
	}

	result := make([]byte, 8)
	for i := 0; i < 8; i++ {
		result[i] = pinBlockPart1[i] ^ panBlockPart2[i]
	}

	return strings.ToUpper(hex.EncodeToString(result)), nil
}

func decodeVISA1(pinBlockHex, pan string) (string, error) {
	if pan == "" {
		return "", errPanRequired
	}
	pinBlockBytes, err := hex.DecodeString(pinBlockHex)
	if err != nil {
		return "", fmt.Errorf("%w: invalid hex for visa1 pin block", errInternalDecoding)
	}

	// Prepare PAN field (same as in encoding).
	panOnlyDigits := ""
	for _, r := range pan {
		if r >= '0' && r <= '9' {
			panOnlyDigits += string(r)
		}
	}

	if panOnlyDigits == "" {
		return "", errPanNoDigits
	}
	if len(panOnlyDigits) < 12 {
		return "", fmt.Errorf(
			"%w: pan must contain at least 12 processable digits for visa1 decoding",
			errInvalidPanLength,
		)
	}
	relevantPan := panOnlyDigits[len(panOnlyDigits)-12:]
	panFieldStr := "0000" + relevantPan
	panBlockPart2, err := hex.DecodeString(panFieldStr)
	if err != nil {
		return "", fmt.Errorf("%w: decoding pan field for visa1", errInternalDecoding)
	}

	// XOR PIN block with PAN field to get the clear PIN field.
	clearPinFieldBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		clearPinFieldBytes[i] = pinBlockBytes[i] ^ panBlockPart2[i]
	}
	clearPinFieldHex := strings.ToUpper(hex.EncodeToString(clearPinFieldBytes))

	// Validate format "LPPPP...". L is PIN length (0x4-0xC).
	pinLenHex := string(clearPinFieldHex[0])
	pinLen, err := strconv.ParseInt(pinLenHex, 16, 64)
	if err != nil || pinLen < 4 || pinLen > 12 { // VISA1 PIN length 4-12.
		return "", fmt.Errorf(
			"%w: decoded visa1 pin block has invalid pin length",
			errPinBlockDecoding,
		)
	}

	// Extract PIN.
	pinStartIndex := 1 // PIN starts after the length character.
	pinEndIndex := pinStartIndex + int(pinLen)
	if pinEndIndex > 16 { // 16 is length of clearPinFieldHex.
		return "", fmt.Errorf("%w: pin length exceeds block boundary in visa1", errPinBlockDecoding)
	}
	pin := clearPinFieldHex[pinStartIndex:pinEndIndex]

	// Validate padding.
	padding := clearPinFieldHex[pinEndIndex:]
	for _, charRune := range padding {
		if charRune != 'F' {
			return "", fmt.Errorf(
				"%w: decoded visa1 pin block has invalid padding character",
				errPinBlockDecoding,
			)
		}
	}

	return pin, nil
}

// ... placeholder functions for other formats ...

func encodeVISA2(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func decodeVISA2(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func encodeVISA3(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func decodeVISA3(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func encodeVISA4(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func decodeVISA4(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func encodeDOCUTEL(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func decodeDOCUTEL(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func encodeNCR(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func decodeNCR(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func encodeECI1(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func decodeECI1(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func encodeDIEBOLD(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func decodeDIEBOLD(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func encodeIBM3624(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func decodeIBM3624(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}
