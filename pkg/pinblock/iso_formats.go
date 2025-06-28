// Package pinblock implements various PIN block encoding and decoding formats.
package pinblock

import (
	"fmt"
	"strconv"
	"strings"
)

// ISO Format 0 (ANSI X9.8 / ISO 9564-1:2017 Format 0).
func encodeISO0(pin, pan string) (string, error) {
	// Block 1 (PIN field): '0' + PIN Length (1 hex char) + PIN + 'F' Fill.
	pinBlock1Str := fmt.Sprintf("0%X%s", len(pin), pin)
	for len(pinBlock1Str) < 16 {
		pinBlock1Str += "F" // Specification: pad character (hexadecimal F)
	}

	if pan == "" {
		return "", errPanRequired
	}
	panDigits := ""
	for _, r := range pan {
		if r >= '0' && r <= '9' {
			panDigits += string(r)
		}
	}
	// pan can be provided as 12 right-most digits excluding  check digit.
	if len(panDigits) < 12 {
		return "", errInvalidPanLength
	}
	relevantPan, err := get12PanDigits(pan, false) // false for fromRight.
	if err != nil {
		return "", err
	}
	panBlock2Str := "0000" + relevantPan

	return xorHexStrings(pinBlock1Str, panBlock2Str)
}

func decodeISO0(pinBlockHex, pan string) (string, error) {
	return decodePanBasedFormat(pinBlockHex, pan, false, '0', "iso0")
}

// ISO Format 1 (ISO 9564-1:2017 Format 1).
// Thales Format 05.
func encodeISO1(pin, _ string) (string, error) { // PAN is not used for ISO1 encoding itself
	// Block (PIN field): '1' + PIN Length (1 hex char) + PIN + Random hexadecimal padding (0-9, A-F).
	pinBlockStr := fmt.Sprintf("1%X%s", len(pin), pin)
	for len(pinBlockStr) < 16 {
		pinBlockStr += GetRandomHexDigit() // Specification: R . . R is random padding.
	}

	return pinBlockStr, nil
}

func decodeISO1(pinBlockHex, _ string) (string, error) { // PAN is not used for ISO1 decoding
	// Validate format "1LPPPP...".
	if len(pinBlockHex) != 16 {
		return "", fmt.Errorf(
			"%w: iso1 pin block must be 16 hex characters",
			errInvalidPinBlockLength,
		)
	}
	if pinBlockHex[0] != '1' {
		return "", fmt.Errorf(
			"%w: decoded iso1 pin block has invalid format prefix, expected '1'",
			errPinBlockDecoding,
		)
	}
	pinLenHex := string(pinBlockHex[1])
	pinLen, err := strconv.ParseInt(pinLenHex, 16, 64)
	// As per Thales spec for Format 05: The second character (N) is in the hexadecimal range 4 - C.
	if err != nil || pinLen < 4 || pinLen > 12 {
		return "", fmt.Errorf(
			"%w: decoded iso1 pin block has invalid pin length (must be 4-C hex)",
			errPinBlockDecoding,
		)
	}

	pinStartIndex := 2
	pinEndIndex := pinStartIndex + int(pinLen)
	if pinEndIndex > 16 { // Should not happen if pinLen is max C (12)
		return "", fmt.Errorf("%w: pin length exceeds block boundary in iso1", errPinBlockDecoding)
	}
	decodedPin := pinBlockHex[pinStartIndex:pinEndIndex]

	// Validate PIN digits are 0-9.
	for _, charRune := range decodedPin {
		if charRune < '0' || charRune > '9' {
			return "", fmt.Errorf(
				"%w: decoded iso1 pin block contains non-numeric PIN characters",
				errPinBlockDecoding,
			)
		}
	}

	// Validate padding characters are valid hexadecimal (0-9, A-F).
	padding := pinBlockHex[pinEndIndex:]
	for _, charRune := range padding {
		if !strings.ContainsRune("0123456789ABCDEF", charRune) {
			return "", fmt.Errorf(
				"%w: decoded iso1 pin block has invalid random padding character",
				errPinBlockDecoding,
			)
		}
	}

	return decodedPin, nil
}

// ISO Format 2 (ISO 9564-1:2017 Format 2).
// Thales Format 34.
func encodeISO2(pin, _ string) (string, error) { // PAN is not used for ISO2 encoding
	// Block: '2' + PIN Length (1 hex char) + PIN + 'F' padding.
	// Thales Spec: C N P P P P P/F P/F P/F P/F P/F P/F P/F P/F F F
	// C = X'2', N = len, P = PIN, F = X'F'
	pinBlockStr := fmt.Sprintf("2%X%s", len(pin), pin)
	for len(pinBlockStr) < 14 {
		pinBlockStr += "F"
	}

	return pinBlockStr, nil
}

func decodeISO2(pinBlockHex, _ string) (string, error) { // PAN is not used for ISO2 decoding
	if len(pinBlockHex) != 14 {
		return "", fmt.Errorf(
			"%w: iso2 pin block must be 14 hex characters",
			errInvalidPinBlockLength,
		)
	}
	// Validate format "2LPPPP...FFFF".
	if pinBlockHex[0] != '2' {
		return "", fmt.Errorf(
			"%w: decoded iso2 pin block has invalid format prefix, expected '2'",
			errPinBlockDecoding,
		)
	}
	pinLenHex := string(pinBlockHex[1])
	pinLen, err := strconv.ParseInt(pinLenHex, 16, 64)
	// Thales Spec: N can be any binary value from 0100 to 1100 (X'4 to X'C).
	if err != nil || pinLen < 4 || pinLen > 12 {
		return "", fmt.Errorf(
			"%w: decoded iso2 pin block has invalid pin length (must be 4-C hex)",
			errPinBlockDecoding,
		)
	}

	pinStartIndex := 2
	pinEndIndex := pinStartIndex + int(pinLen)
	if pinEndIndex > 14 {
		return "", fmt.Errorf("%w: pin length exceeds block boundary in iso2", errPinBlockDecoding)
	}
	decodedPin := pinBlockHex[pinStartIndex:pinEndIndex]

	// Validate PIN digits are 0-9.
	for _, charRune := range decodedPin {
		if charRune < '0' || charRune > '9' {
			return "", fmt.Errorf(
				"%w: decoded iso2 pin block contains non-numeric PIN characters",
				errPinBlockDecoding,
			)
		}
	}

	// Validate padding is 'F'.
	padding := pinBlockHex[pinEndIndex:]
	for _, charRune := range padding {
		if charRune != 'F' {
			return "", fmt.Errorf(
				"%w: decoded iso2 pin block has invalid padding, expected 'F'",
				errPinBlockDecoding,
			)
		}
	}

	return decodedPin, nil
}

// ISO Format 3 (ISO 9564-1:2017 Format 3).
// Thales Format 47.
func encodeISO3(pin, pan string) (string, error) {
	// Plain text PIN field: '3' + PIN Length (1 hex char) + PIN + Random Fill (A-F).
	// Thales Spec: C N P P P P P/F P/F P/F P/F P/F P/F P/F P/F F F
	// C = X'3', N = len, P = PIN, F = Random A-F
	pinFieldStr := fmt.Sprintf("3%X%s", len(pin), pin)
	for len(pinFieldStr) < 16 {
		pinFieldStr += GetRandomHexDigitAF() // Specification: Fill digit (A-F)
	}

	// Account number field: '0000' + 12 right-most digits of PAN (excluding check digit).
	relevantPan, err := get12PanDigits(pan, false) // false for fromRight.
	if err != nil {
		return "", err
	}
	panFieldStr := "0000" + relevantPan

	// XOR the two blocks.
	return xorHexStrings(pinFieldStr, panFieldStr)
}

func decodeISO3(pinBlockHex, pan string) (string, error) {
	if len(pinBlockHex) != 16 {
		return "", fmt.Errorf(
			"%w: iso3 pin block must be 16 hex characters",
			errInvalidPinBlockLength,
		)
	}
	// Account number field: '0000' + 12 right-most digits of PAN (excluding check digit).
	relevantPan, err := get12PanDigits(pan, false) // false for fromRight.
	if err != nil {
		return "", err
	}
	panFieldStr := "0000" + relevantPan

	// XOR PIN block with PAN field to get clear plain text PIN field.
	clearPinFieldHex, err := xorHexStrings(pinBlockHex, panFieldStr)
	if err != nil {
		return "", fmt.Errorf("%w: xor failed during iso3 decoding: %v", errInternalDecoding, err)
	}

	// Validate format "3LPPPP...FFFF".
	if clearPinFieldHex[0] != '3' {
		return "", fmt.Errorf(
			"%w: decoded iso3 clear pin field has invalid format prefix, expected '3'",
			errPinBlockDecoding,
		)
	}
	pinLenHex := string(clearPinFieldHex[1])
	pinLen, err := strconv.ParseInt(pinLenHex, 16, 64)
	// Thales Spec: N can be any binary value from 0100 to 1100 (X'4 to X'C).
	if err != nil || pinLen < 4 || pinLen > 12 {
		return "", fmt.Errorf(
			"%w: decoded iso3 clear pin field has invalid pin length (must be 4-C hex)",
			errPinBlockDecoding,
		)
	}

	pinStartIndex := 2
	pinEndIndex := pinStartIndex + int(pinLen)
	if pinEndIndex > 16 {
		return "", fmt.Errorf(
			"%w: pin length exceeds block boundary in iso3 clear pin field",
			errPinBlockDecoding,
		)
	}
	decodedPin := clearPinFieldHex[pinStartIndex:pinEndIndex]

	// Validate PIN digits are 0-9.
	for _, charRune := range decodedPin {
		if charRune < '0' || charRune > '9' {
			return "", fmt.Errorf(
				"%w: decoded iso3 clear pin field contains non-numeric PIN characters",
				errPinBlockDecoding,
			)
		}
	}

	// Validate padding characters are (A-F).
	padding := clearPinFieldHex[pinEndIndex:]
	for _, charRune := range padding {
		if !strings.ContainsRune("ABCDEF", charRune) {
			return "", fmt.Errorf(
				"%w: decoded iso3 clear pin field has invalid random fill character (expected A-F)",
				errPinBlockDecoding,
			)
		}
	}

	return decodedPin, nil
}

// ISO Format 4 (ISO 9564-1:2017 Format 4).
// Thales Format 48.
func encodeISO4(_, _ string) (string, error) {
	// Implementation specific to ISO Format 4.
	// Uses AES, not DES/3DES like others here.

	return "", errFormatNotImplemented
}

func decodeISO4(_, _ string) (string, error) {
	// Implementation specific to ISO Format 4.

	return "", errFormatNotImplemented
}

// ECI Format 1: similar to ISO1 but uses random hex digits for padding.
// This was an existing interpretation. Based on Thales spec, ISO1 (Format 05) itself uses random padding.
// So ECI1 and ISO1 become effectively the same under this interpretation.
func encodeECI1(_, _ string) (string, error) {
	// ECI1 format is not implemented.
	return "", errFormatNotImplemented
}

// decodeECI1 decodes an ECI Format 1 PIN block, same as ISO1 decoding.
func decodeECI1(_, _ string) (string, error) {
	// ECI1 format is not implemented.
	return "", errFormatNotImplemented
}
