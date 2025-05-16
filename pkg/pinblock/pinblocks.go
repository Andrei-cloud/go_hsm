// Package pinblock implements various PIN block encoding and decoding formats.
package pinblock

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// Supported PIN block formats.
// This list is based on common industry standards.
// Not all formats listed here are implemented in this example; for full implementation,
// detailed specifications for each format are required.
const (
	ISO0    PinBlockFormat = iota // ISO 9564-1 Format 0.
	ISO1                          // ISO 9564-1 Format 1.
	ISO2                          // ISO 9564-1 Format 2.
	ISO3                          // ISO 9564-1 Format 3.
	ISO4                          // ISO 9564-1 Format 4.
	ANSIX98                       // ANSI X9.8.
	VISA1                         // VISA VTS PIN Block Format 1.
	ECI1                          // ECI Format 1.
	DIEBOLD                       // Diebold Format.
	IBM3624                       // IBM 3624 Format.
	VISA2                         // VISA VTS PIN Block Format 2.
	VISA3                         // VISA VTS PIN Block Format 3.
	VISA4                         // VISA VTS PIN Block Format 4.
	DOCUTEL                       // Docutel PIN Block Format.
	NCR                           // NCR PIN Block Format.
	// Added based on Thales specification.
	PLUSNETWORK              // Thales Format 04 (PLUS Network).
	MASTERCARDPAYNOWPAYLATER // Thales Format 35 (Mastercard Pay Now & Pay Later).
	VISANEWPINONLY           // Thales Format 41 (Visa new PIN only).
	VISANEWOLDIN             // Thales Format 42 (Visa new & old PIN).
	// Each requires its specific encoding/decoding algorithm from standard documents.
)

var (
	errInvalidPinLength      = errors.New("invalid pin length")
	errInvalidPanLength      = errors.New("invalid pan length")
	errInvalidPinBlockLength = errors.New("invalid pin block length")
	errInvalidPinBlockFormat = errors.New("unsupported or invalid pin block format")
	errPinBlockDecoding      = errors.New("pin block decoding failed")
	errPanRequired           = errors.New("pan is required for this pin block format")
	errPanNoDigits           = errors.New("pan contains no processable digits")
	errInternalEncoding      = errors.New("internal error during encoding")
	errInternalDecoding      = errors.New("internal error during decoding")
	errRandomGeneration      = errors.New("failed to generate random data")
	errFormatNotImplemented  = errors.New("pin block format not implemented")
)

// PinBlockFormat defines the type for PIN block formats.
// Each format specifies a method for encrypting or formatting a PIN.
type PinBlockFormat int

// EncodePinBlock creates a PIN block from a PIN and PAN (if required by the format).
// PIN should be a string of 4-12 digits.
// PAN, if used, should be the account number string; relevant parts are extracted as per format spec.
// Returns the PIN block as an uppercase hex string.
func EncodePinBlock(pin, pan string, format PinBlockFormat) (string, error) {
	if len(pin) < 4 || len(pin) > 12 {
		return "", errInvalidPinLength
	}
	for _, r := range pin {
		if r < '0' || r > '9' {
			return "", fmt.Errorf("pin contains non-digit characters: %w", errInvalidPinLength)
		}
	}

	switch format {
	case ISO0:
		return encodeISO0(pin, pan)
	case ISO1:
		return encodeISO1(pin, pan)
	case ISO2:
		return encodeISO2(pin, pan)
	case ISO3:
		return encodeISO3(pin, pan)
	case ISO4:
		return encodeISO4(pin, pan)
	case ANSIX98:
		return encodeANSIX98(pin, pan)
	case VISA1:
		return encodeVISA1(pin, pan)
	case ECI1:
		return encodeECI1(pin, pan)
	case DIEBOLD:
		return encodeDIEBOLD(pin, pan)
	case IBM3624:
		return encodeIBM3624(pin, pan)
	case VISA2:
		return encodeVISA2(pin, pan)
	case VISA3:
		return encodeVISA3(pin, pan)
	case VISA4:
		return encodeVISA4(pin, pan)
	case DOCUTEL:
		return encodeDOCUTEL(pin, pan)
	case NCR:
		return encodeNCR(pin, pan)
	case PLUSNETWORK:
		return encodePLUSNETWORK(pin, pan)
	case MASTERCARDPAYNOWPAYLATER:
		return encodeMASTERCARDPAYNOWPAYLATER(pin, pan)
	case VISANEWPINONLY:
		return encodeVISANEWPINONLY(pin, pan)
	case VISANEWOLDIN:
		return encodeVISANEWOLDIN(pin, pan)
	default:
		return "", errInvalidPinBlockFormat
	}
}

// DecodePinBlock extracts the PIN from a PIN block and PAN (if required by the format).
// pinBlockHex is the PIN block as an uppercase or lowercase hex string.
// PAN, if used, should be the account number string.
// Returns the extracted PIN as a string of digits.
func DecodePinBlock(pinBlockHex, pan string, format PinBlockFormat) (string, error) {
	if len(pinBlockHex) != 16 {
		return "", errInvalidPinBlockLength
	}
	// Normalize to uppercase for consistent processing, though hex.DecodeString handles both.
	pinBlockHex = strings.ToUpper(pinBlockHex)
	_, err := hex.DecodeString(pinBlockHex) // Validate hex.
	if err != nil {
		return "", fmt.Errorf("pin block is not a valid hex string: %w", errInvalidPinBlockLength)
	}

	switch format {
	case ISO0:
		return decodeISO0(pinBlockHex, pan)
	case ISO1:
		return decodeISO1(pinBlockHex, pan)
	case ISO2:
		return decodeISO2(pinBlockHex, pan)
	case ISO3:
		return decodeISO3(pinBlockHex, pan)
	case ISO4:
		return decodeISO4(pinBlockHex, pan)
	case ANSIX98:
		return decodeANSIX98(pinBlockHex, pan)
	case VISA1:
		return decodeVISA1(pinBlockHex, pan)
	case ECI1:
		return decodeECI1(pinBlockHex, pan)
	case DIEBOLD:
		return decodeDIEBOLD(pinBlockHex, pan)
	case IBM3624:
		return decodeIBM3624(pinBlockHex, pan)
	case VISA2:
		return decodeVISA2(pinBlockHex, pan)
	case VISA3:
		return decodeVISA3(pinBlockHex, pan)
	case VISA4:
		return decodeVISA4(pinBlockHex, pan)
	case DOCUTEL:
		return decodeDOCUTEL(pinBlockHex, pan)
	case NCR:
		return decodeNCR(pinBlockHex, pan)
	case PLUSNETWORK:
		return decodePLUSNETWORK(pinBlockHex, pan)
	case MASTERCARDPAYNOWPAYLATER:
		return decodeMASTERCARDPAYNOWPAYLATER(pinBlockHex, pan)
	case VISANEWPINONLY:
		return decodeVISANEWPINONLY(pinBlockHex, pan)
	case VISANEWOLDIN:
		return decodeVISANEWOLDIN(pinBlockHex, pan)
	default:
		return "", errInvalidPinBlockFormat
	}
}

// GetGenerator returns a function to encode a PIN block based on the format code.
func GetGenerator(formatCode string) func(pin, pan string) (string, error) {
	formatMap := map[string]PinBlockFormat{
		"01": ISO0,
		"02": DOCUTEL,
		"03": IBM3624,
		"04": PLUSNETWORK,
		"05": ISO1,
		"34": ISO2,
		"35": MASTERCARDPAYNOWPAYLATER,
		"41": VISANEWPINONLY,
		"42": VISANEWOLDIN,
		"47": ISO3,
		"48": ISO4,
	}

	format, exists := formatMap[formatCode]
	if !exists {
		return func(pin, pan string) (string, error) {
			return "", fmt.Errorf("unsupported format code: %s", formatCode)
		}
	}

	return func(pin, pan string) (string, error) {
		return EncodePinBlock(pin, pan, format)
	}
}
