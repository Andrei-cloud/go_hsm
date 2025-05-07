package pinblock

import (
	"fmt"
	"strconv"
)

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
