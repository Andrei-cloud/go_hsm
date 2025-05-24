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

	// Block 1 (PIN data): '0' + PIN Length (1 hex char) + PIN + 'F' padding.
	pinFieldStr := fmt.Sprintf("0%X%s", len(pin), pin)
	for len(pinFieldStr) < 16 {
		pinFieldStr += "F"
	}
	pinBlockPart1, err := hex.DecodeString(pinFieldStr)
	if err != nil {
		return "", fmt.Errorf("%w: encoding pin field for ansix98", errInternalEncoding)
	}

	// Block 2 (PAN data): '0000' + 12 rightmost digits of PAN (excluding check digit).
	relevantPan, err := get12PanDigits(pan, false)
	if err != nil {
		return "", err
	}
	panFieldStr := "0000" + relevantPan
	panBlockPart2, err := hex.DecodeString(panFieldStr)
	if err != nil {
		return "", fmt.Errorf("%w: encoding pan field for ansix98", errInternalEncoding)
	}

	// XOR Block 1 and Block 2.
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

	// Validate PAN first before checking pin block length.
	relevantPan, err := get12PanDigits(pan, false)
	if err != nil {
		return "", err
	}

	if len(pinBlockHex) != 16 {
		return "", fmt.Errorf(
			"%w: ansix98 pin block must be 16 hex characters",
			errInvalidPinBlockLength,
		)
	}

	pinBlockBytes, err := hex.DecodeString(pinBlockHex)
	if err != nil {
		return "", fmt.Errorf("%w: invalid hex for ansix98 pin block", errInternalDecoding)
	}
	if len(pinBlockBytes) != 8 {
		return "", fmt.Errorf(
			"%w: ansix98 pin block must be 8 bytes after decoding",
			errInvalidPinBlockLength,
		)
	}

	// Prepare PAN field (same as encoding).
	panFieldStr := "0000" + relevantPan
	panBlockPart2, err := hex.DecodeString(panFieldStr)
	if err != nil {
		return "", fmt.Errorf("%w: decoding pan field for ansix98", errInternalDecoding)
	}

	// XOR PIN block with PAN field to get clear PIN field.
	clearPinFieldBytes := make([]byte, 8)
	for i := 0; i < 8; i++ {
		clearPinFieldBytes[i] = pinBlockBytes[i] ^ panBlockPart2[i]
	}
	clearPinFieldHex := strings.ToUpper(hex.EncodeToString(clearPinFieldBytes))
	// Validate basic length first.
	if len(clearPinFieldHex) < 16 {
		return "", fmt.Errorf(
			"%w: decoded ansix98 pin block is too short",
			errPinBlockDecoding,
		)
	}

	// Try to extract PIN length for validation (even if format is wrong).
	pinLenHex := string(clearPinFieldHex[1])
	pinLen, err := strconv.ParseInt(pinLenHex, 16, 64)
	if err == nil && (pinLen < 4 || pinLen > 14) {
		return "", fmt.Errorf(
			"%w: decoded ansix98 pin block has invalid pin length",
			errPinBlockDecoding,
		)
	}

	// Now validate format "0LPPPP...". First char must be '0'.
	if clearPinFieldHex[0] != '0' {
		return "", fmt.Errorf(
			"%w: decoded ansix98 pin block has invalid format",
			errPinBlockDecoding,
		)
	}

	// Re-validate PIN length parsing with proper error handling.
	if err != nil {
		return "", fmt.Errorf(
			"%w: decoded ansix98 pin block has invalid format",
			errPinBlockDecoding,
		)
	}

	// Extract PIN.
	pinStartIndex := 2                           // Skip '0' and length chars.
	pinEndIndex := pinStartIndex + int(pinLen)   // End at pin length.
	if pinStartIndex >= len(clearPinFieldHex) || // Start must be in range.
		pinEndIndex > len(clearPinFieldHex) { // End must be in range.
		return "", fmt.Errorf("%w: decoded ansix98 pin block length error", errPinBlockDecoding)
	}
	decodedPin := clearPinFieldHex[pinStartIndex:pinEndIndex]

	// Validate remaining digits.
	padding := clearPinFieldHex[pinEndIndex:]
	for _, charRune := range padding {
		if charRune != 'F' {
			return "", fmt.Errorf(
				"%w: decoded ansix98 pin block has invalid padding character",
				errPinBlockDecoding,
			)
		}
	}

	return decodedPin, nil
}

// Thales Format 02 (Docutel ATM).
// PIN: 4-6 digits (original length). PIN in block is 6 digits, left-justified, zero-filled.
// The 'pan' argument is used as the numeric padding string.
// If pan (padding string) is empty or too short, a default or error will be used.
func encodeDOCUTEL(pin, numericPaddingString string) (string, error) {
	originalPinLen := len(pin)
	if originalPinLen < 4 ||
		originalPinLen > 6 { // As per Thales example context (PIN 92389, len 5)
		return "", fmt.Errorf(
			"%w: original pin length must be 4-6 for docutel",
			errInvalidPinLength,
		)
	}

	formattedPin := pin
	for len(formattedPin) < 6 {
		formattedPin += "0" // Left-justified, zero-filled to 6 digits.
	}

	// PIN length char.
	pinLenChar := fmt.Sprintf("%X", originalPinLen) // Example: 5 for PIN "92389".

	// Padding.
	// The block is L + PPPPPP + RRRRRRRRR (1 + 6 + 9 = 16 chars).
	// So, padding must be 9 numeric characters.
	if len(numericPaddingString) != 9 {
		return "", fmt.Errorf(
			"%w: docutel numeric padding string must be 9 digits long",
			errInvalidPanLength,
		)
	}
	for _, r := range numericPaddingString {
		if r < '0' || r > '9' {
			return "", fmt.Errorf(
				"%w: docutel numeric padding string must contain only digits",
				errInvalidPanLength,
			)
		}
	}

	return strings.ToUpper(pinLenChar + formattedPin + numericPaddingString), nil
}

func decodeDOCUTEL(pinBlockHex, numericPaddingString string) (string, error) {
	if len(pinBlockHex) != 16 {
		return "", errInvalidPinBlockLength
	}

	pinLenHex := string(pinBlockHex[0])
	originalPinLen, err := strconv.ParseInt(pinLenHex, 16, 64)
	if err != nil || originalPinLen < 4 || originalPinLen > 6 {
		return "", fmt.Errorf(
			"%w: decoded docutel pin block has invalid original pin length",
			errPinBlockDecoding,
		)
	}

	// Formatted PIN is 6 chars.
	// formattedPinInBlock := pinBlockHex[1:7] // Not needed directly for PIN extraction.

	// Expected padding.
	if len(numericPaddingString) != 9 {
		return "", fmt.Errorf(
			"%w: docutel numeric padding string for decoding must be 9 digits long",
			errInvalidPanLength,
		)
	}
	// Validate that the provided padding string matches the one in the block.
	if pinBlockHex[7:] != numericPaddingString {
		return "", fmt.Errorf("%w: docutel padding mismatch", errPinBlockDecoding)
	}

	// Extract the original PIN from the 6-digit zero-padded PIN.
	// The first `originalPinLen` characters of the 6-digit PIN part are the actual PIN.
	fullPaddedPin := pinBlockHex[1 : 1+6]
	pin := fullPaddedPin[:originalPinLen]

	// Validate that the remaining part of the 6-digit PIN field was zeros.
	for i := int(originalPinLen); i < 6; i++ {
		if fullPaddedPin[i] != '0' {
			return "", fmt.Errorf(
				"%w: decoded docutel pin block has invalid zero padding in pin field",
				errPinBlockDecoding,
			)
		}
	}

	return pin, nil
}

// Thales Format 03 (Diebold & IBM ATM).
// PIN block: customer PIN + hexadecimal F padding.
func encodeDIEBOLD(pin, _ string) (string, error) {
	// PIN length 4-12 assumed validated by caller.
	// For Diebold, PIN length can be up to 16 if it's all numeric.
	// Thales spec example: 5-digit PIN 92389 -> 92389FFFFFFFFFFF.
	if len(pin) > 16 {
		return "", fmt.Errorf("%w: pin too long for diebold (max 16)", errInvalidPinLength)
	}
	pinBlockStr := pin
	for len(pinBlockStr) < 16 {
		pinBlockStr += "F"
	}

	return strings.ToUpper(pinBlockStr), nil
}

func decodeDIEBOLD(pinBlockHex, _ string) (string, error) {
	if len(pinBlockHex) != 16 {
		return "", errInvalidPinBlockLength
	}

	// Find the end of the PIN by looking for consecutive F's that represent padding.
	pinEndIndex := 16 // Start from the end and work backwards.
	for i := 15; i >= 0; i-- {
		if pinBlockHex[i] != 'F' {
			pinEndIndex = i + 1
			break
		}
	}

	// Validate all characters are valid hex digits.
	for i := 0; i < 16; i++ {
		char := pinBlockHex[i]
		if !((char >= '0' && char <= '9') || (char >= 'A' && char <= 'F')) {
			return "", fmt.Errorf(
				"%w: diebold pin block contains non-digit non-F char",
				errPinBlockDecoding,
			)
		}
	}

	if pinEndIndex == 0 { // All F's.
		return "", fmt.Errorf("%w: diebold pin block contains no pin digits", errPinBlockDecoding)
	}
	pin := pinBlockHex[:pinEndIndex]

	// Validate padding (should be all F's after PIN).
	for i := pinEndIndex; i < 16; i++ {
		if pinBlockHex[i] != 'F' {
			return "", fmt.Errorf(
				"%w: diebold pin block has invalid byte",
				errPinBlockDecoding,
			)
		}
	}

	return pin, nil
}

// Thales Format 03 (IBM 3624) - Same as Diebold.
func encodeIBM3624(pin, pan string) (string, error) {
	return encodeDIEBOLD(pin, pan)
}

func decodeIBM3624(pinBlockHex, pan string) (string, error) {
	return decodeDIEBOLD(pinBlockHex, pan)
}

// NCR Format: not implemented.
func encodeNCR(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func decodeNCR(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}
