
package pinblock

import (
	"strings"
	"testing"
)

type pinBlockTestCase struct {
	name          string
	pin           string
	pan           string
	udkHex        string
	wantEncodeHex string
	wantErrEncode error
	wantErrDecode error
}

func testPinBlockFormat(t *testing.T, format PinBlockFormat, tc pinBlockTestCase) {
	t.Helper()

	encodeFn, decodeFn, err := getFormatFuncs(format)
	if err != nil {
		t.Fatalf("getFormatFuncs() error = %v", err)
	}

	// Determine the second argument for the functions
	var secondArg string
	switch format {
	case VISANEWPINONLY:
		secondArg = tc.udkHex
	default:
		secondArg = tc.pan
	}

	encodedHex, err := encodeFn(tc.pin, secondArg)
	if tc.wantErrEncode != nil {
		if err == nil || !strings.Contains(err.Error(), tc.wantErrEncode.Error()) {
			t.Errorf("encode() error = %v, wantErr %v", err, tc.wantErrEncode)
		}
		return
	}
	if err != nil {
		t.Fatalf("encode() unexpected error = %v", err)
	}
	if tc.wantEncodeHex != "" && encodedHex != tc.wantEncodeHex {
		t.Errorf("encode() got = %v, want %v", encodedHex, tc.wantEncodeHex)
	}

	decodedPin, err := decodeFn(encodedHex, secondArg)
	if tc.wantErrDecode != nil {
		if err == nil || !strings.Contains(err.Error(), tc.wantErrDecode.Error()) {
			t.Errorf("decode() error = %v, wantErr %v", err, tc.wantErrDecode)
		}
		return
	}
	if err != nil {
		t.Fatalf("decode() unexpected error = %v", err)
	}
	if decodedPin != tc.pin {
		t.Errorf("decode() got = %v, want %v", decodedPin, tc.pin)
	}
}

func getFormatFuncs(format PinBlockFormat) (func(string, string) (string, error), func(string, string) (string, error), error) {
	switch format {
	case ISO0:
		return encodeISO0, decodeISO0, nil
	case ISO1:
		return encodeISO1, decodeISO1, nil
	case ISO2:
		return encodeISO2, decodeISO2, nil
	case ISO3:
		return encodeISO3, decodeISO3, nil
	case ISO4:
		return encodeISO4, decodeISO4, nil
	case ANSIX98:
		return encodeANSIX98, decodeANSIX98, nil
	case VISA1:
		return encodeVISA1, decodeVISA1, nil
	case DOCUTEL:
		return encodeDOCUTEL, decodeDOCUTEL, nil
	case DIEBOLD:
		return encodeDIEBOLD, decodeDIEBOLD, nil
	case IBM3624:
		return encodeIBM3624, decodeIBM3624, nil
	case PLUSNETWORK:
		return encodePLUSNETWORK, decodePLUSNETWORK, nil
	case MASTERCARDPAYNOWPAYLATER:
		return encodeMASTERCARDPAYNOWPAYLATER, decodeMASTERCARDPAYNOWPAYLATER, nil
	case VISANEWPINONLY:
		return encodeVISANEWPINONLY, decodeVISANEWPINONLY, nil
	case VISANEWOLDIN:
		return encodeVISANEWOLDIN, decodeVISANEWOLDIN, nil
	default:
		return nil, nil, errFormatNotImplemented
	}
}
