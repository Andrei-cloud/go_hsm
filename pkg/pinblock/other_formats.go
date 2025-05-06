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

	pinEndIndex := 0
	for i, char := range pinBlockHex {
		if char == 'F' {
			break
		}
		if char < '0' || char > '9' {
			return "", fmt.Errorf(
				"%w: diebold pin block contains non-digit non-F char",
				errPinBlockDecoding,
			)
		}
		pinEndIndex = i + 1
	}

	if pinEndIndex == 0 { // All F's or empty (not possible due to length check).
		return "", fmt.Errorf("%w: diebold pin block contains no pin digits", errPinBlockDecoding)
	}
	pin := pinBlockHex[:pinEndIndex]

	// Validate padding.
	for i := pinEndIndex; i < 16; i++ {
		if pinBlockHex[i] != 'F' {
			return "", fmt.Errorf(
				"%w: diebold pin block has invalid padding character",
				errPinBlockDecoding,
			)
		}
	}

	// Relaxing this check as Thales spec for Format 03 doesn't specify PIN length range directly,
	// but refers to "customer PIN".
	// Basic length check for PIN (e.g. 4-12 or 4-16).
	// Thales usually implies 4-12 for PINs unless specified.

	return pin, nil
}

// Thales Format 03 (IBM 3624) - Same as Diebold.
func encodeIBM3624(pin, pan string) (string, error) {
	return encodeDIEBOLD(pin, pan)
}

func decodeIBM3624(pinBlockHex, pan string) (string, error) {
	return decodeDIEBOLD(pinBlockHex, pan)
}

// Helper to XOR two hex strings. Result is uppercase hex.
func xorHexStrings(s1, s2 string) (string, error) {
	b1, err := hex.DecodeString(s1)
	if err != nil {
		return "", fmt.Errorf("invalid hex string s1: %w", err)
	}
	b2, err := hex.DecodeString(s2)
	if err != nil {
		return "", fmt.Errorf("invalid hex string s2: %w", err)
	}

	if len(b1) != len(b2) {
		return "", fmt.Errorf(
			"hex strings must have equal length to xor (s1 len %d, s2 len %d)",
			len(b1),
			len(b2),
		)
	}

	resultBytes := make([]byte, len(b1))
	for i := 0; i < len(b1); i++ {
		resultBytes[i] = b1[i] ^ b2[i]
	}

	return strings.ToUpper(hex.EncodeToString(resultBytes)), nil
}

// Helper to get 12 digits from PAN (left or right).
func get12PanDigits(pan string, fromLeft bool) (string, error) {
	panDigits := ""
	for _, r := range pan {
		if r >= '0' && r <= '9' {
			panDigits += string(r)
		}
	}
	if len(panDigits) < 12 {
		return "", fmt.Errorf("%w: pan must contain at least 12 digits", errInvalidPanLength)
	}
	if fromLeft {
		return panDigits[:12], nil
	}
	// from right, excluding check digit (standard interpretation for "rightmost 12 excluding check digit")
	if panDigits != "" { // panDigits has already been filtered for digits.
		panWithoutCheckDigit := panDigits[:len(panDigits)-1]
		if len(panWithoutCheckDigit) < 12 {
			return "", fmt.Errorf(
				"%w: pan (after excluding check digit) must contain at least 12 digits",
				errInvalidPanLength,
			)
		}

		return panWithoutCheckDigit[len(panWithoutCheckDigit)-12:], nil
	}

	return "", errPanNoDigits // Should be caught by len(panDigits) < 12 earlier.
}

// Thales Format 04 (PLUS Network).
func encodePLUSNETWORK(pin, pan string) (string, error) {
	// Block 1 (PIN data): '0' + PIN Length (1 hex char) + PIN + 'F' padding.
	pinFieldStr := fmt.Sprintf("0%X%s", len(pin), pin)
	for len(pinFieldStr) < 16 {
		pinFieldStr += "F"
	}

	// Block 2 (PAN data): '0000' + 12 left-most digits of account number.
	relevantPan, err := get12PanDigits(pan, true) // true for fromLeft.
	if err != nil {
		return "", err
	}
	panFieldStr := "0000" + relevantPan

	return xorHexStrings(pinFieldStr, panFieldStr)
}

func decodePLUSNETWORK(pinBlockHex, pan string) (string, error) {
	// Block 2 (PAN data): '0000' + 12 left-most digits of account number.
	relevantPan, err := get12PanDigits(pan, true) // true for fromLeft.
	if err != nil {
		return "", err
	}
	panFieldStr := "0000" + relevantPan

	// XOR PIN block with PAN field to get the clear PIN field (Block 1).
	clearPinFieldHex, err := xorHexStrings(pinBlockHex, panFieldStr)
	if err != nil {
		return "", fmt.Errorf(
			"%w: xor failed during plus network decoding: %v",
			errInternalDecoding,
			err,
		)
	}

	// Validate format "0LPPPP...".
	if clearPinFieldHex[0] != '0' {
		return "", fmt.Errorf(
			"%w: decoded plus network pin block has invalid format prefix",
			errPinBlockDecoding,
		)
	}
	pinLenHex := string(clearPinFieldHex[1])
	pinLen, err := strconv.ParseInt(pinLenHex, 16, 64)
	if err != nil || pinLen < 4 || pinLen > 12 { // Standard PIN length.
		return "", fmt.Errorf(
			"%w: decoded plus network pin block has invalid pin length",
			errPinBlockDecoding,
		)
	}

	pinStartIndex := 2
	pinEndIndex := pinStartIndex + int(pinLen)
	if pinEndIndex > 16 {
		return "", fmt.Errorf(
			"%w: pin length exceeds block boundary in plus network",
			errPinBlockDecoding,
		)
	}
	decodedPin := clearPinFieldHex[pinStartIndex:pinEndIndex]

	// Validate padding.
	padding := clearPinFieldHex[pinEndIndex:]
	for _, charRune := range padding {
		if charRune != 'F' {
			return "", fmt.Errorf(
				"%w: decoded plus network pin block has invalid padding",
				errPinBlockDecoding,
			)
		}
	}

	return decodedPin, nil
}

// Thales Format 35 (Mastercard Pay Now & Pay Later).
func encodeMASTERCARDPAYNOWPAYLATER(pin, pan string) (string, error) {
	// Block 1 (PIN field): '2' + PIN Length (1 hex char) + PIN + 'F' padding (like ISO2).
	pinBlock1Str := fmt.Sprintf("2%X%s", len(pin), pin)
	for len(pinBlock1Str) < 16 {
		pinBlock1Str += "F"
	}

	// Block 2 (PAN field): '0000' + 12 right-most digits of account number, excluding check digit (like ISO0).
	relevantPan, err := get12PanDigits(pan, false) // false for fromRight (excluding check digit).
	if err != nil {
		return "", err
	}
	panBlock2Str := "0000" + relevantPan

	return xorHexStrings(pinBlock1Str, panBlock2Str)
}

func decodeMASTERCARDPAYNOWPAYLATER(pinBlockHex, pan string) (string, error) {
	// Block 2 (PAN field): '0000' + 12 right-most digits of account number, excluding check digit.
	relevantPan, err := get12PanDigits(pan, false) // false for fromRight.
	if err != nil {
		return "", err
	}
	panBlock2Str := "0000" + relevantPan

	// XOR PIN block with PAN field to get clear PIN field (Block 1).
	clearPinFieldHex, err := xorHexStrings(pinBlockHex, panBlock2Str)
	if err != nil {
		return "", fmt.Errorf(
			"%w: xor failed during mastercard paynowpaylater decoding: %v",
			errInternalDecoding,
			err,
		)
	}

	// Validate format "2LPPPP..." (like ISO2).
	if clearPinFieldHex[0] != '2' {
		return "", fmt.Errorf(
			"%w: decoded mastercard pin block has invalid format prefix",
			errPinBlockDecoding,
		)
	}
	pinLenHex := string(clearPinFieldHex[1])
	pinLen, err := strconv.ParseInt(pinLenHex, 16, 64)
	if err != nil || pinLen < 4 || pinLen > 12 {
		return "", fmt.Errorf(
			"%w: decoded mastercard pin block has invalid pin length",
			errPinBlockDecoding,
		)
	}

	pinStartIndex := 2
	pinEndIndex := pinStartIndex + int(pinLen)
	if pinEndIndex > 16 {
		return "", fmt.Errorf(
			"%w: pin length exceeds block boundary in mastercard",
			errPinBlockDecoding,
		)
	}
	decodedPin := clearPinFieldHex[pinStartIndex:pinEndIndex]

	// Validate padding.
	padding := clearPinFieldHex[pinEndIndex:]
	for _, charRune := range padding {
		if charRune != 'F' {
			return "", fmt.Errorf(
				"%w: decoded mastercard pin block has invalid padding",
				errPinBlockDecoding,
			)
		}
	}

	return decodedPin, nil
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

// `pinBlockHex` is the block, `pan` (repurposed) is UDK_HEX.
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

// `pinBlockHex` is the block.
// `newPin` (unused in decode for PIN itself, but part of signature).
// `oldPinAndUdkHex` is "OLDPIN|UDKHEX".
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

// Stubs for ECI1, VISA2, VISA3, VISA4, NCR formats.
// These would require specific implementation details based on their standards.

func encodeECI1(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func decodeECI1(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

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

func encodeNCR(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}

func decodeNCR(_, _ string) (string, error) {
	return "", errFormatNotImplemented
}
