
package pinblock

import (
	"fmt"
	"strconv"
)

// decodePanBasedFormat provides a generic decoding mechanism for PIN block formats
// that are based on XORing a PIN field with a PAN-derived field.
func decodePanBasedFormat(pinBlockHex, pan string, panFromLeft bool, formatPrefix byte, formatName string) (string, error) {
	// Step 1: Construct the PAN-derived field.
	relevantPan, err := get12PanDigits(pan, panFromLeft)
	if err != nil {
		return "", fmt.Errorf("failed to get relevant PAN for %s: %w", formatName, err)
	}
	panFieldStr := "0000" + relevantPan

	// Step 2: XOR the encrypted PIN block with the PAN field to get the clear PIN field.
	clearPinFieldHex, err := xorHexStrings(pinBlockHex, panFieldStr)
	if err != nil {
		return "", fmt.Errorf("%w: xor failed during %s decoding: %v", errInternalDecoding, formatName, err)
	}

	// Step 3: Validate the format of the clear PIN field.
	if clearPinFieldHex[0] != formatPrefix {
		return "", fmt.Errorf(
			"%w: decoded %s pin block has invalid format prefix, expected '%c'",
			errPinBlockDecoding,
			formatName,
			formatPrefix,
		)
	}

	// Step 4: Extract the PIN length and the PIN itself.
	pinLenHex := string(clearPinFieldHex[1])
	pinLen, err := strconv.ParseInt(pinLenHex, 16, 64)
	if err != nil || pinLen < 4 || pinLen > 12 {
		return "", fmt.Errorf(
			"%w: decoded %s pin block has invalid pin length",
			errPinBlockDecoding,
			formatName,
		)
	}

	pinStartIndex := 2
	pinEndIndex := pinStartIndex + int(pinLen)
	if pinEndIndex > 16 {
		return "", fmt.Errorf("%w: pin length exceeds block boundary in %s", errPinBlockDecoding, formatName)
	}
	decodedPin := clearPinFieldHex[pinStartIndex:pinEndIndex]

	// Step 5: Validate the padding.
	padding := clearPinFieldHex[pinEndIndex:]
	for _, charRune := range padding {
		if charRune != 'F' {
			return "", fmt.Errorf(
				"%w: decoded %s pin block has invalid padding, expected 'F'",
				errPinBlockDecoding,
				formatName,
			)
		}
	}

	return decodedPin, nil
}
