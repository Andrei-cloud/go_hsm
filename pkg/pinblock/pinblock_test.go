package pinblock

import (
	"fmt"
	"testing"
)

func TestEncodeDecodeISO0(t *testing.T) {
	t.Parallel()
	tests := []pinBlockTestCase{
		{name: "valid iso0", pin: "1234", pan: "1111222233334444"},
		{name: "valid iso0 longer pin", pin: "123456789012", pan: "1111222233334444"},
		{name: "missing pan", pin: "1234", pan: "", wantErrEncode: errPanRequired, wantErrDecode: errPanRequired},
		{name: "short pan", pin: "1234", pan: "123", wantErrEncode: errInvalidPanLength, wantErrDecode: errInvalidPanLength},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testPinBlockFormat(t, ISO0, tc)
		})
	}
}

func TestEncodeDecodeISO1(t *testing.T) {
	t.Parallel()
	tests := []pinBlockTestCase{
		{name: "valid iso1", pin: "1234"},
		{name: "valid iso1 longer pin", pin: "123456789012"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testPinBlockFormat(t, ISO1, tc)
		})
	}
}

func TestEncodeDecodeISO2(t *testing.T) {
	t.Parallel()
	tests := []pinBlockTestCase{
		{name: "valid iso2", pin: "1234"},
		{name: "valid iso2 longer pin", pin: "123456789012"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testPinBlockFormat(t, ISO2, tc)
		})
	}
}

func TestEncodeDecodeISO3(t *testing.T) {
	t.Parallel()
	tests := []pinBlockTestCase{
		{name: "valid iso3", pin: "1234", pan: "1111222233334444"},
		{name: "valid iso3 longer pin", pin: "123456789012", pan: "1111222233334444"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testPinBlockFormat(t, ISO3, tc)
		})
	}
}

func TestEncodeDecodeANSIX98(t *testing.T) {
	t.Parallel()
	tests := []pinBlockTestCase{
		{name: "valid ansix98", pin: "123456", pan: "1234567890123456"},
		{name: "valid ansix98 pin 14", pin: "12345678901234", pan: "1234567890123456"},
		{name: "ansix98 missing pan", pin: "1234", pan: "", wantErrEncode: errPanRequired, wantErrDecode: errPanRequired},
		{name: "ansix98 pan too short", pin: "1234", pan: "123", wantErrEncode: errInvalidPanLength, wantErrDecode: errInvalidPanLength},
		{name: "ansix98 pan no digits", pin: "1234", pan: "ABC", wantErrEncode: errPanNoDigits, wantErrDecode: errPanNoDigits},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testPinBlockFormat(t, ANSIX98, tc)
		})
	}
}

func TestEncodeDecodeVISA1(t *testing.T) {
	t.Parallel()
	tests := []pinBlockTestCase{
		{name: "valid visa1", pin: "1234", pan: "1234567890123456"},
		{name: "valid visa1 pin 12", pin: "123456789012", pan: "1234567890123456"},
		{name: "visa1 missing pan", pin: "1234", pan: "", wantErrEncode: errPanRequired, wantErrDecode: errPanRequired},
		{name: "visa1 pan too short", pin: "1234", pan: "123", wantErrEncode: errInvalidPanLength, wantErrDecode: errInvalidPanLength},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testPinBlockFormat(t, VISA1, tc)
		})
	}
}

func TestEncodeDecodeDOCUTEL(t *testing.T) {
	t.Parallel()
	tests := []pinBlockTestCase{
		{name: "valid docutel pin 4", pin: "1234", pan: "123456789", wantEncodeHex: "4123400123456789"},
		{name: "valid docutel pin 6", pin: "123456", pan: "987654321", wantEncodeHex: "6123456987654321"},
		{name: "docutel pin too short", pin: "123", pan: "123456789", wantErrEncode: errInvalidPinLength},
		{name: "docutel pin too long", pin: "1234567", pan: "123456789", wantErrEncode: errInvalidPinLength},
		{name: "docutel padding too short", pin: "1234", pan: "123", wantErrEncode: errInvalidPanLength},
		{name: "docutel padding non-numeric", pin: "1234", pan: "12345678A", wantErrEncode: errInvalidPanLength},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testPinBlockFormat(t, DOCUTEL, tc)
		})
	}
}

func TestEncodeDecodeDIEBOLD(t *testing.T) {
	t.Parallel()
	tests := []pinBlockTestCase{
		{name: "valid DIEBOLD", pin: "12345", wantEncodeHex: "12345FFFFFFFFFFF"},
		{name: "valid DIEBOLD pin 10", pin: "0123456789", wantEncodeHex: "0123456789FFFFFF"},
		{name: "DIEBOLD pin too long", pin: "0123456789ABCDEFG", wantErrEncode: errInvalidPinLength},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testPinBlockFormat(t, DIEBOLD, tc)
		})
	}
}

func TestEncodeDecodeIBM3624(t *testing.T) {
	t.Parallel()
	tests := []pinBlockTestCase{
		{name: "valid IBM3624", pin: "12345", wantEncodeHex: "12345FFFFFFFFFFF"},
		{name: "valid IBM3624 pin 10", pin: "0123456789", wantEncodeHex: "0123456789FFFFFF"},
		{name: "IBM3624 pin too long", pin: "0123456789ABCDEFG", wantErrEncode: errInvalidPinLength},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testPinBlockFormat(t, IBM3624, tc)
		})
	}
}

func TestEncodeDecodePLUSNETWORK(t *testing.T) {
	t.Parallel()
	tests := []pinBlockTestCase{
		{name: "valid plusnetwork", pin: "1234", pan: "123456789012"},
		{name: "plusnetwork pan too short", pin: "1234", pan: "123", wantErrEncode: errInvalidPanLength, wantErrDecode: errInvalidPanLength},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testPinBlockFormat(t, PLUSNETWORK, tc)
		})
	}
}

func TestEncodeDecodeMASTERCARDPAYNOWPAYLATER(t *testing.T) {
	t.Parallel()
	tests := []pinBlockTestCase{
		{name: "valid mastercard", pin: "1234", pan: "1234567890123"},
		{name: "mastercard pan too short", pin: "1234", pan: "123", wantErrEncode: errInvalidPanLength, wantErrDecode: errInvalidPanLength},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testPinBlockFormat(t, MASTERCARDPAYNOWPAYLATER, tc)
		})
	}
}

func TestEncodeDecodeVISANEWPINONLY(t *testing.T) {
	t.Parallel()
	tests := []pinBlockTestCase{
		{name: "valid visa new pin only", pin: "1234", udkHex: "0123456789ABCDEF"},
		{name: "visa new pin only udk too short", pin: "1234", udkHex: "1234567", wantErrEncode: errInvalidPanLength, wantErrDecode: errInvalidPanLength},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testPinBlockFormat(t, VISANEWPINONLY, tc)
		})
	}
}

func TestEncodeDecodeVISANEWOLDIN(t *testing.T) {
	t.Parallel()
	tests := []pinBlockTestCase{
		{name: "valid visa new old in", pin: "5678", pan: "1234|0123456789ABCDEF"},
		{name: "visa new old in invalid oldpinudk format", pin: "5678", pan: "1234_01234567", wantErrEncode: errInvalidPanLength, wantErrDecode: errInvalidPanLength},
		{name: "visa new old in udk too short", pin: "5678", pan: "1234|123456", wantErrEncode: errInvalidPanLength, wantErrDecode: errInvalidPanLength},
		{name: "visa new old in oldpin too short", pin: "5678", pan: "123|01234567", wantErrEncode: errInvalidPinLength, wantErrDecode: errInvalidPanLength},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			testPinBlockFormat(t, VISANEWOLDIN, tc)
		})
	}
}

func TestNotImplementedFormats(t *testing.T) {
	t.Parallel()
	formats := []PinBlockFormat{
		ECI1,
		VISA2,
		VISA3,
		VISA4,
		NCR,
	}

	for _, format := range formats {
		t.Run(fmt.Sprintf("%d", format), func(t *testing.T) {
			t.Parallel()
			_, _, err := getFormatFuncs(format)
			if err == nil {
				t.Errorf("getFormatFuncs() error = %v, wantErr %v", err, errFormatNotImplemented)
			}
		})
	}
}