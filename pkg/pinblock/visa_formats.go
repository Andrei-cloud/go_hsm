package pinblock

import (
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
)

// VISA1 format implementation.
// PIN: 4-12 digits.
// PAN: The 11 rightmost digits of the PAN (excluding the check digit) are used.
// The 12th digit is the check digit of the PAN.
func encodeVISA1(pin, pan string) (string, error) {
	if pan == "" {
		return "", errPanRequired
	}

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
	relevantPan, err := get12PanDigits(pan, false) // PAN validation done here.
	if err != nil {
		return "", err
	}
	panFieldStr := "0000" + relevantPan
	panBlockPart2, err := hex.DecodeString(panFieldStr)
	if err != nil {
		return "", fmt.Errorf("%w: encoding pan field for visa1", errInternalEncoding)
	}

	// XOR Block 1 and Block 2.
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
	if len(pinBlockBytes) != 8 {
		return "", fmt.Errorf("%w: visa1 pin block must be 8 bytes", errInvalidPinBlockLength)
	}

	// Prepare PAN field (same as in encoding).
	relevantPan, err := get12PanDigits(pan, false)
	if err != nil {
		return "", err
	}
	panFieldStr := "0000" + relevantPan
	panBlockPart2, err := hex.DecodeString(panFieldStr)
	if err != nil {
		return "", fmt.Errorf("%w: decoding pan field for visa1", errInternalDecoding)
	}
	if len(panBlockPart2) != 8 {
		return "", fmt.Errorf(
			"%w: pan field for visa1 must be 8 bytes after processing",
			errInternalDecoding,
		)
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

// VISA2 PIN block format.
func encodeVISA2(_, _ string) (string, error) {
	// Implementation specific to VISA2.
	return "", errFormatNotImplemented
}

func decodeVISA2(_, _ string) (string, error) {
	// Implementation specific to VISA2.
	return "", errFormatNotImplemented
}

// VISA3 PIN block format.
func encodeVISA3(_, _ string) (string, error) {
	// Implementation specific to VISA3.
	return "", errFormatNotImplemented
}

func decodeVISA3(_, _ string) (string, error) {
	// Implementation specific to VISA3.
	return "", errFormatNotImplemented
}

// VISA4 PIN block format.
func encodeVISA4(_, _ string) (string, error) {
	// Implementation specific to VISA4.
	return "", errFormatNotImplemented
}

func decodeVISA4(_, _ string) (string, error) {
	// Implementation specific to VISA4.
	return "", errFormatNotImplemented
}

// Thales Format 41 (Visa new PIN only).
// `pin` is new PIN, `pan` (repurposed) is UDK_HEX.
func encodeVISANEWPINONLY(newPin, udkHex string) (string, error) {
	if len(udkHex) < 8 { // Needs 8 rightmost hex digits.
		return "", fmt.Errorf(
			"%w: udkHex too short for visa41 (min 8 hex chars)",
			errInvalidPanLength,
		)
	}

	// Step 1 (Key Block): '00000000' + 8 rightmost digits of UDK.
	keyBlockStr := "00000000" + udkHex[len(udkHex)-8:]

	// Step 2 (PIN Data Block): '0' + New PIN Length + New PIN + 'F' padding.
	pinDataBlockStr := fmt.Sprintf("0%X%s", len(newPin), newPin)
	for len(pinDataBlockStr) < 16 {
		pinDataBlockStr += "F"
	}

	// Step 3: XOR.
	return xorHexStrings(keyBlockStr, pinDataBlockStr)
}

func decodeVISANEWPINONLY(pinBlockHex, udkHex string) (string, error) {
	if len(udkHex) < 8 {
		return "", fmt.Errorf(
			"%w: udkHex too short for visa41 decoding (min 8 hex chars)",
			errInvalidPanLength,
		)
	}
	keyBlockStr := "00000000" + udkHex[len(udkHex)-8:]

	// XOR with keyBlock to get clear PIN Data Block.
	clearPinDataBlockHex, err := xorHexStrings(pinBlockHex, keyBlockStr)
	if err != nil {
		return "", fmt.Errorf("%w: xor failed during visa41 decoding: %v", errInternalDecoding, err)
	}

	// Validate format "0LPPPP...".
	if clearPinDataBlockHex[0] != '0' {
		return "", fmt.Errorf(
			"%w: decoded visa41 pin block has invalid format prefix",
			errPinBlockDecoding,
		)
	}
	pinLenHex := string(clearPinDataBlockHex[1])
	pinLen, err := strconv.ParseInt(pinLenHex, 16, 64)
	if err != nil || pinLen < 4 || pinLen > 12 {
		return "", fmt.Errorf(
			"%w: decoded visa41 pin block has invalid pin length",
			errPinBlockDecoding,
		)
	}

	pinStartIndex := 2
	pinEndIndex := pinStartIndex + int(pinLen)
	if pinEndIndex > 16 {
		return "", fmt.Errorf(
			"%w: pin length exceeds block boundary in visa41",
			errPinBlockDecoding,
		)
	}
	decodedPin := clearPinDataBlockHex[pinStartIndex:pinEndIndex]

	// Validate padding.
	padding := clearPinDataBlockHex[pinEndIndex:]
	for _, charRune := range padding {
		if charRune != 'F' {
			return "", fmt.Errorf(
				"%w: decoded visa41 pin block has invalid padding",
				errPinBlockDecoding,
			)
		}
	}

	return decodedPin, nil
}

// Thales Format 42 (Visa new & old PIN).
// `newPin` is the new PIN.
// `panAndOldPinAndUdk` is "OLDPIN|UDKHEX".
func encodeVISANEWOLDIN(newPin, oldPinAndUdkHex string) (string, error) {
	parts := strings.Split(oldPinAndUdkHex, "|")
	if len(parts) != 2 {
		return "", fmt.Errorf(
			"%w: invalid format for oldPinAndUdkHex, expected 'OLDPIN|UDKHEX'",
			errInvalidPanLength,
		)
	}
	oldPin := parts[0]
	udkHex := parts[1]

	if len(udkHex) < 8 {
		return "", fmt.Errorf(
			"%w: udkHex too short for visa42 (min 8 hex chars)",
			errInvalidPanLength,
		)
	}
	if len(oldPin) < 4 || len(oldPin) > 12 { // Assuming old PIN also 4-12.
		return "", fmt.Errorf("%w: old pin length invalid for visa42", errInvalidPinLength)
	}

	// Step 1 (Key Block): '00000000' + 8 rightmost UDK.
	keyBlockStr := "00000000" + udkHex[len(udkHex)-8:]

	// Step 2 (New PIN Data Block): '0' + New PIN Length + New PIN + 'F' padding.
	newPinDataBlockStr := fmt.Sprintf("0%X%s", len(newPin), newPin)
	for len(newPinDataBlockStr) < 16 {
		newPinDataBlockStr += "F"
	}

	// Step 3 (Old PIN Data Block): Old PIN + '0' padding to 16 hex chars.
	oldPinDataBlockStr := oldPin
	for len(oldPinDataBlockStr) < 16 {
		oldPinDataBlockStr += "0"
	}

	// Step 4: XOR all three.
	intermediateXor, err := xorHexStrings(keyBlockStr, newPinDataBlockStr)
	if err != nil {
		return "", fmt.Errorf("%w: visa42 xor step 1 failed: %v", errInternalEncoding, err)
	}

	return xorHexStrings(intermediateXor, oldPinDataBlockStr)
}

func decodeVISANEWOLDIN(pinBlockHex, oldPinAndUdkHex string) (string, error) {
	parts := strings.Split(oldPinAndUdkHex, "|")
	if len(parts) != 2 {
		return "", fmt.Errorf(
			"%w: invalid format for oldPinAndUdkHex for visa42 decoding, expected 'OLDPIN|UDKHEX'",
			errInvalidPanLength,
		)
	}
	oldPin := parts[0]
	udkHex := parts[1]

	if len(udkHex) < 8 {
		return "", fmt.Errorf(
			"%w: udkHex too short for visa42 decoding (min 8 hex chars)",
			errInvalidPanLength,
		)
	}
	if len(oldPin) < 4 || len(oldPin) > 12 {
		return "", fmt.Errorf("%w: old pin length invalid for visa42 decoding", errInvalidPinLength)
	}

	// Reconstruct the three blocks used in encoding.
	keyBlockStr := "00000000" + udkHex[len(udkHex)-8:]
	oldPinDataBlockStr := oldPin
	for len(oldPinDataBlockStr) < 16 {
		oldPinDataBlockStr += "0"
	}

	// XOR pinBlockHex with keyBlockStr and oldPinDataBlockStr to get the New PIN Data Block.
	// P_final = B1 ^ B2 ^ B3  => B2 = P_final ^ B1 ^ B3
	intermediateXor, err := xorHexStrings(pinBlockHex, keyBlockStr)
	if err != nil {
		return "", fmt.Errorf("%w: visa42 decode xor step 1 failed: %v", errInternalDecoding, err)
	}
	clearNewPinDataBlockHex, err := xorHexStrings(intermediateXor, oldPinDataBlockStr)
	if err != nil {
		return "", fmt.Errorf("%w: visa42 decode xor step 2 failed: %v", errInternalDecoding, err)
	}

	// Validate format "0LPPPP..." for the New PIN Data Block.
	if clearNewPinDataBlockHex[0] != '0' {
		return "", fmt.Errorf(
			"%w: decoded visa42 new pin block has invalid format prefix",
			errPinBlockDecoding,
		)
	}
	pinLenHex := string(clearNewPinDataBlockHex[1])
	pinLen, err := strconv.ParseInt(pinLenHex, 16, 64)
	if err != nil || pinLen < 4 || pinLen > 12 {
		return "", fmt.Errorf(
			"%w: decoded visa42 new pin block has invalid pin length",
			errPinBlockDecoding,
		)
	}

	pinStartIndex := 2
	pinEndIndex := pinStartIndex + int(pinLen)
	if pinEndIndex > 16 {
		return "", fmt.Errorf(
			"%w: new pin length exceeds block boundary in visa42",
			errPinBlockDecoding,
		)
	}
	decodedNewPin := clearNewPinDataBlockHex[pinStartIndex:pinEndIndex]

	// Validate padding.
	padding := clearNewPinDataBlockHex[pinEndIndex:]
	for _, charRune := range padding {
		if charRune != 'F' {
			return "", fmt.Errorf(
				"%w: decoded visa42 new pin block has invalid padding",
				errPinBlockDecoding,
			)
		}
	}

	return decodedNewPin, nil // Returns the new PIN.
}
