package pinblock

import (
	"fmt"
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
	return decodePanBasedFormat(pinBlockHex, pan, true, '0', "plus network")
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
	return decodePanBasedFormat(pinBlockHex, pan, false, '2', "mastercard paynowpaylater")
}
