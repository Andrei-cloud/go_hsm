package pinblock

import (
	"strings"
	"testing"
)

func TestEncodeDecodeISO4(t *testing.T) {
	t.Parallel()
	// ISO4 is not implemented.
	t.Run("encodeISO4 not implemented", func(t *testing.T) {
		t.Parallel()
		_, err := encodeISO4("1234", "1111222233334444")
		if err == nil || !strings.Contains(err.Error(), errFormatNotImplemented.Error()) {
			t.Errorf("encodeISO4() error = %v, wantErr %v", err, errFormatNotImplemented)
		}
	})
	t.Run("decodeISO4 not implemented", func(t *testing.T) {
		t.Parallel()
		_, err := decodeISO4("ANYBLOCK", "1111222233334444")
		if err == nil || !strings.Contains(err.Error(), errFormatNotImplemented.Error()) {
			t.Errorf("decodeISO4() error = %v, wantErr %v", err, errFormatNotImplemented)
		}
	})
}

// Tests for functions in other_formats.go.

func TestEncodeDecodeANSIX98(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		pin           string
		pan           string
		wantErrEncode error
		wantErrDecode error
	}{
		{
			name: "valid ansix98",
			pin:  "123456",
			pan:  "1234567890123456",
		}, // PAN: ...9012345 (12 rightmost excluding check '6').
		{name: "valid ansix98 pin 14", pin: "12345678901234", pan: "1234567890123456"},
		{
			name:          "ansix98 missing pan",
			pin:           "1234",
			pan:           "",
			wantErrEncode: errPanRequired,
			wantErrDecode: errPanRequired,
		},
		{
			name:          "ansix98 pan too short",
			pin:           "1234",
			pan:           "123",
			wantErrEncode: errInvalidPanLength,
			wantErrDecode: errInvalidPanLength,
		},
		{
			name:          "ansix98 pan no digits",
			pin:           "1234",
			pan:           "ABC",
			wantErrEncode: errPanNoDigits,
			wantErrDecode: errPanNoDigits,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			encodedHex, err := encodeANSIX98(tt.pin, tt.pan)
			if tt.wantErrEncode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrEncode.Error()) {
					t.Errorf("encodeANSIX98() error = %v, wantErr %v", err, tt.wantErrEncode)
				}
				// If encode fails as expected, try to test decode with its specific error if provided
				if tt.wantErrDecode != nil &&
					tt.wantErrEncode == tt.wantErrDecode { // only if same error expected for decode path
					_, decErr := decodeANSIX98(
						"DUMMYBLOCK",
						tt.pan,
					) // Use dummy block for decode path check
					if decErr == nil ||
						!strings.Contains(decErr.Error(), tt.wantErrDecode.Error()) {
						t.Errorf(
							"decodeANSIX98() for pan error check error = %v, wantErr %v",
							decErr,
							tt.wantErrDecode,
						)
					}

					return
				}
			}
			if err != nil {
				t.Fatalf("encodeANSIX98() unexpected error = %v", err)
			}

			decodedPin, err := decodeANSIX98(encodedHex, tt.pan)
			if tt.wantErrDecode != nil { // This path for when encode succeeds but decode might fail for other reasons
				if err == nil || !strings.Contains(err.Error(), tt.wantErrDecode.Error()) {
					t.Errorf("decodeANSIX98() error = %v, wantErr %v", err, tt.wantErrDecode)
				}

				return
			}
			if err != nil {
				t.Fatalf("decodeANSIX98() unexpected error = %v", err)
			}
			if decodedPin != tt.pin {
				t.Errorf("decodeANSIX98() got = %v, want %v", decodedPin, tt.pin)
			}
		})
	}
	// Specific decode error cases.
	t.Run("decodeANSIX98 invalid pin length in block", func(t *testing.T) {
		t.Parallel()
		panForZeroXOR := "0000000000000000"    // so panBlockPart2 is 0000000000000000.
		clearPinFieldHex := "3123FFFFFFFFFFFF" // PIN length 3 (too short for ANSI X9.8: 4-14).
		pinBlockHex, _ := xorHexStrings(clearPinFieldHex, "0000000000000000")
		_, err := decodeANSIX98(pinBlockHex, panForZeroXOR)
		if err == nil || !strings.Contains(err.Error(), "invalid pin length") {
			t.Errorf("decodeANSIX98() with too short pin length error = %v", err)
		}

		clearPinFieldHex = "F123456789012345" // PIN length 15 (too long for ANSI X9.8: 4-14).
		pinBlockHex, _ = xorHexStrings(clearPinFieldHex, "0000000000000000")
		_, err = decodeANSIX98(pinBlockHex, panForZeroXOR)
		if err == nil || !strings.Contains(err.Error(), "invalid pin length") {
			t.Errorf("decodeANSIX98() with too long pin length error = %v", err)
		}
	})

	t.Run("decodeANSIX98 invalid padding", func(t *testing.T) {
		t.Parallel()
		panForZeroXOR := "0000000000000000"
		clearPinFieldHex := "41234FFFFFFFFFFG" // Invalid padding 'G'.
		pinBlockHex, _ := xorHexStrings(clearPinFieldHex, "0000000000000000")
		_, err := decodeANSIX98(pinBlockHex, panForZeroXOR)
		if err == nil || !strings.Contains(err.Error(), "invalid pin block length") {
			t.Errorf("decodeANSIX98() with invalid padding error = %v", err)
		}
	})
}

func TestEncodeDecodeVISA1(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		pin           string
		pan           string
		wantErrEncode error
		wantErrDecode error
	}{
		{name: "valid visa1", pin: "1234", pan: "1234567890123456"}, // PAN: ...890123456 (last 12).
		{name: "valid visa1 pin 12", pin: "123456789012", pan: "1234567890123456"},
		{
			name:          "visa1 missing pan",
			pin:           "1234",
			pan:           "",
			wantErrEncode: errPanRequired,
			wantErrDecode: errPanRequired,
		},
		{
			name:          "visa1 pan too short",
			pin:           "1234",
			pan:           "123",
			wantErrEncode: errInvalidPanLength,
			wantErrDecode: errInvalidPanLength,
		},
	}
	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			encodedHex, err := encodeVISA1(tt.pin, tt.pan)
			if tt.wantErrEncode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrEncode.Error()) {
					t.Errorf("encodeVISA1() error = %v, wantErr %v", err, tt.wantErrEncode)
				}
				// Test decode path for same error if applicable
				if tt.wantErrDecode != nil && tt.wantErrEncode == tt.wantErrDecode {
					_, decErr := decodeVISA1("DUMMYBLOCK", tt.pan)
					if decErr == nil ||
						!strings.Contains(decErr.Error(), tt.wantErrDecode.Error()) {
						t.Errorf(
							"decodeVISA1() for pan error check error = %v, wantErr %v",
							decErr,
							tt.wantErrDecode,
						)
					}
				}

				return
			}
			if err != nil {
				t.Fatalf("encodeVISA1() unexpected error = %v", err)
			}

			decodedPin, err := decodeVISA1(encodedHex, tt.pan)
			if tt.wantErrDecode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrDecode.Error()) {
					t.Errorf("decodeVISA1() error = %v, wantErr %v", err, tt.wantErrDecode)
				}

				return
			}
			if err != nil {
				t.Fatalf("decodeVISA1() unexpected error = %v", err)
			}
			if decodedPin != tt.pin {
				t.Errorf("decodeVISA1() got = %v, want %v", decodedPin, tt.pin)
			}
		})
	}
	// Specific decode error cases.
	t.Run("decodeVISA1 invalid pin length in block", func(t *testing.T) {
		t.Parallel()
		panForZeroXOR := "0000000000000000"
		clearPinFieldHex := "3123FFFFFFFFFFFF" // PIN length 3 (too short for VISA1: 4-12).
		pinBlockHex, _ := xorHexStrings(clearPinFieldHex, "0000000000000000")
		_, err := decodeVISA1(pinBlockHex, panForZeroXOR)
		if err == nil || !strings.Contains(err.Error(), "invalid pin length") {
			t.Errorf("decodeVISA1() with too short pin length error = %v", err)
		}

		clearPinFieldHex = "D1234567890123" // PIN length 13 (too long for VISA1: 4-12).
		pinBlockHex, _ = xorHexStrings(clearPinFieldHex, "0000000000000000")
		_, err = decodeVISA1(pinBlockHex, panForZeroXOR)
		if err == nil || !strings.Contains(err.Error(), "invalid pin block length") {
			t.Errorf("decodeVISA1() with too long pin length error = %v", err)
		}
	})
}

func TestEncodeDecodeDOCUTEL(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		pin            string
		numericPadding string
		wantEncodeHex  string
		wantErrEncode  error
		wantErrDecode  error
	}{
		{
			name:           "valid docutel pin 4",
			pin:            "1234",
			numericPadding: "123456789",
			wantEncodeHex:  "4123400123456789",
		},
		{
			name:           "valid docutel pin 6",
			pin:            "123456",
			numericPadding: "987654321",
			wantEncodeHex:  "6123456987654321",
		},
		{
			name:           "docutel pin too short",
			pin:            "123",
			numericPadding: "123456789",
			wantErrEncode:  errInvalidPinLength,
		},
		{
			name:           "docutel pin too long",
			pin:            "1234567",
			numericPadding: "123456789",
			wantErrEncode:  errInvalidPinLength,
		},
		{
			name:           "docutel padding too short",
			pin:            "1234",
			numericPadding: "123",
			wantErrEncode:  errInvalidPanLength,
		}, // errInvalidPanLength used for padding issues.
		{
			name:           "docutel padding non-numeric",
			pin:            "1234",
			numericPadding: "12345678A",
			wantErrEncode:  errInvalidPanLength,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			encodedHex, err := encodeDOCUTEL(tt.pin, tt.numericPadding)
			if tt.wantErrEncode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrEncode.Error()) {
					t.Errorf("encodeDOCUTEL() error = %v, wantErr %v", err, tt.wantErrEncode)
				}

				return
			}
			if err != nil {
				t.Fatalf("encodeDOCUTEL() unexpected error = %v", err)
			}
			if encodedHex != tt.wantEncodeHex {
				t.Errorf("encodeDOCUTEL() got = %v, want %v", encodedHex, tt.wantEncodeHex)
			}

			decodedPin, err := decodeDOCUTEL(encodedHex, tt.numericPadding)
			if tt.wantErrDecode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrDecode.Error()) {
					t.Errorf("decodeDOCUTEL() error = %v, wantErr %v", err, tt.wantErrDecode)
				}

				return
			}
			if err != nil {
				t.Fatalf("decodeDOCUTEL() unexpected error = %v", err)
			}
			if decodedPin != tt.pin {
				t.Errorf("decodeDOCUTEL() got = %v, want %v", decodedPin, tt.pin)
			}
		})
	}
	// Specific decode error cases.
	t.Run("decodeDOCUTEL invalid block length", func(t *testing.T) {
		t.Parallel()
		_, err := decodeDOCUTEL("SHORT", "123456789")
		if err == nil || !strings.Contains(err.Error(), errInvalidPinBlockLength.Error()) {
			t.Errorf("decodeDOCUTEL() with short block error = %v", err)
		}
	})
	t.Run("decodeDOCUTEL invalid original pin length in block", func(t *testing.T) {
		t.Parallel()
		_, err := decodeDOCUTEL("3123000123456789", "123456789") // Original len 3.
		if err == nil || !strings.Contains(err.Error(), "invalid original pin length") {
			t.Errorf("decodeDOCUTEL() with invalid original pin length error = %v", err)
		}
	})
	t.Run("decodeDOCUTEL padding mismatch", func(t *testing.T) {
		t.Parallel()
		_, err := decodeDOCUTEL(
			"4123400123456789",
			"987654321",
		) // Correct block, wrong decode padding.
		if err == nil || !strings.Contains(err.Error(), "padding mismatch") {
			t.Errorf("decodeDOCUTEL() with padding mismatch error = %v", err)
		}
	})
	t.Run("decodeDOCUTEL invalid zero padding in pin field", func(t *testing.T) {
		t.Parallel()
		// pin "1234", originalPinLen 4. formattedPin "123400". Block "4123400...".
		// If formattedPin was "123401", this should fail.
		// Block: L + PaddedPIN(6) + Padding(9).
		// PaddedPIN: PIN + Zeros. If PIN is "1234" (len 4), PaddedPIN is "123400".
		// If block has "4123410..." (instead of "4123400..."), it's an error.
		_, err := decodeDOCUTEL("4123410123456789", "123456789")
		if err == nil || !strings.Contains(err.Error(), "invalid zero padding in pin field") {
			t.Errorf("decodeDOCUTEL() with invalid zero padding error = %v", err)
		}
	})
}

func TestEncodeDecodeDIEBOLD(t *testing.T) {
	t.Parallel()
	// Diebold and IBM3624 are the same.
	runDieboldLikeTests := func(t *testing.T, formatName string,
		encodeFn func(string, string) (string, error),
		decodeFn func(string, string) (string, error),
	) {
		tests := []struct {
			name          string
			pin           string
			pan           string // unused for Diebold/IBM3624.
			wantEncodeHex string
			wantErrEncode error
			wantErrDecode error
		}{
			{name: "valid " + formatName, pin: "12345", wantEncodeHex: "12345FFFFFFFFFFF"},
			{
				name:          "valid " + formatName + " pin 10",
				pin:           "0123456789",
				wantEncodeHex: "0123456789FFFFFF",
			}, // Max 16 for Diebold if all numeric.
			{
				name:          formatName + " pin too long",
				pin:           "0123456789ABCDEFG",
				wantErrEncode: errInvalidPinLength,
			},
		}

		for _, tt := range tests {
			tt := tt // capture range variable.
			t.Run(tt.name, func(t *testing.T) {
				t.Parallel()
				encodedHex, err := encodeFn(tt.pin, tt.pan)
				if tt.wantErrEncode != nil {
					if err == nil || !strings.Contains(err.Error(), tt.wantErrEncode.Error()) {
						t.Errorf(
							"%s encode error = %v, wantErr %v",
							formatName,
							err,
							tt.wantErrEncode,
						)
					}

					return
				}
				if err != nil {
					t.Fatalf("%s encode unexpected error = %v", formatName, err)
				}
				if encodedHex != tt.wantEncodeHex {
					t.Errorf(
						"%s encode got = %v, want %v",
						formatName,
						encodedHex,
						tt.wantEncodeHex,
					)
				}

				decodedPin, err := decodeFn(encodedHex, tt.pan)
				if tt.wantErrDecode != nil {
					if err == nil || !strings.Contains(err.Error(), tt.wantErrDecode.Error()) {
						t.Errorf(
							"%s decode error = %v, wantErr %v",
							formatName,
							err,
							tt.wantErrDecode,
						)
					}

					return
				}
				if err != nil {
					t.Fatalf("%s decode unexpected error = %v", formatName, err)
				}
				if decodedPin != tt.pin {
					t.Errorf("%s decode got = %v, want %v", formatName, decodedPin, tt.pin)
				}
			})
		}
		// Specific decode error cases.
		t.Run(formatName+" decode invalid block length", func(t *testing.T) {
			t.Parallel()
			_, err := decodeFn("SHORT", "")
			if err == nil || !strings.Contains(err.Error(), errInvalidPinBlockLength.Error()) {
				t.Errorf("%s decode with short block error = %v", formatName, err)
			}
		})
		t.Run(formatName+" decode non-digit non-F char", func(t *testing.T) {
			t.Parallel()
			_, err := decodeFn("123GFFFFFFFFFFFF", "")
			if err == nil || !strings.Contains(err.Error(), "non-digit non-F char") {
				t.Errorf("%s decode with invalid char error = %v", formatName, err)
			}
		})
		t.Run(formatName+" decode invalid padding char", func(t *testing.T) {
			t.Parallel()
			_, err := decodeFn("1234FFFFFFFFFFFG", "")
			if err == nil || !strings.Contains(err.Error(), "non-digit non-F char") {
				t.Errorf("%s decode with invalid padding error = %v", formatName, err)
			}
		})
	}

	t.Run("Diebold", func(t *testing.T) {
		t.Parallel()
		runDieboldLikeTests(t, "DIEBOLD", encodeDIEBOLD, decodeDIEBOLD)
	})
	t.Run("IBM3624", func(t *testing.T) {
		t.Parallel()
		runDieboldLikeTests(t, "IBM3624", encodeIBM3624, decodeIBM3624)
	})
}

func TestEncodeDecodePLUSNETWORK(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		pin           string
		pan           string
		wantErrEncode error
		wantErrDecode error
	}{
		{name: "valid plusnetwork", pin: "1234", pan: "123456789012"},
		{
			name:          "plusnetwork pan too short",
			pin:           "1234",
			pan:           "123",
			wantErrEncode: errInvalidPanLength,
			wantErrDecode: errInvalidPanLength,
		},
	}
	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			encodedHex, err := encodePLUSNETWORK(tt.pin, tt.pan)
			if tt.wantErrEncode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrEncode.Error()) {
					t.Errorf("encodePLUSNETWORK() error = %v, wantErr %v", err, tt.wantErrEncode)
				}
				if tt.wantErrDecode != nil && tt.wantErrEncode == tt.wantErrDecode {
					_, decErr := decodePLUSNETWORK("DUMMYBLOCK", tt.pan)
					if decErr == nil ||
						!strings.Contains(decErr.Error(), tt.wantErrDecode.Error()) {
						t.Errorf(
							"decodePLUSNETWORK() for pan error check error = %v, wantErr %v",
							decErr,
							tt.wantErrDecode,
						)
					}
				}

				return
			}
			if err != nil {
				t.Fatalf("encodePLUSNETWORK() unexpected error = %v", err)
			}

			decodedPin, err := decodePLUSNETWORK(encodedHex, tt.pan)
			if tt.wantErrDecode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrDecode.Error()) {
					t.Errorf("decodePLUSNETWORK() error = %v, wantErr %v", err, tt.wantErrDecode)
				}

				return
			}
			if err != nil {
				t.Fatalf("decodePLUSNETWORK() unexpected error = %v", err)
			}
			if decodedPin != tt.pin {
				t.Errorf("decodePLUSNETWORK() got = %v, want %v", decodedPin, tt.pin)
			}
		})
	}
	// Specific decode error cases.
	t.Run("decodePLUSNETWORK invalid format prefix", func(t *testing.T) {
		t.Parallel()
		panForZeroXOR := "0000000000000000"    // PAN part will be 0000000000000000.
		clearPinFieldHex := "141234FFFFFFFFFF" // Invalid prefix '1'.
		pinBlockHex, _ := xorHexStrings(clearPinFieldHex, "0000000000000000")
		_, err := decodePLUSNETWORK(pinBlockHex, panForZeroXOR)
		if err == nil || !strings.Contains(err.Error(), "invalid format prefix") {
			t.Errorf("decodePLUSNETWORK() with invalid prefix error = %v", err)
		}
	})
}

func TestEncodeDecodeMASTERCARDPAYNOWPAYLATER(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		pin           string
		pan           string
		wantErrEncode error
		wantErrDecode error
	}{
		{
			name: "valid mastercard",
			pin:  "1234",
			pan:  "1234567890123",
		}, // Needs 12 rightmost excluding check.
		{
			name:          "mastercard pan too short",
			pin:           "1234",
			pan:           "123",
			wantErrEncode: errInvalidPanLength,
			wantErrDecode: errInvalidPanLength,
		},
	}
	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			encodedHex, err := encodeMASTERCARDPAYNOWPAYLATER(tt.pin, tt.pan)
			if tt.wantErrEncode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrEncode.Error()) {
					t.Errorf(
						"encodeMASTERCARDPAYNOWPAYLATER() error = %v, wantErr %v",
						err,
						tt.wantErrEncode,
					)
				}
				// ... (similar error check for decode path if applicable)

				return
			}
			if err != nil {
				t.Fatalf("encodeMASTERCARDPAYNOWPAYLATER() unexpected error = %v", err)
			}

			decodedPin, err := decodeMASTERCARDPAYNOWPAYLATER(encodedHex, tt.pan)
			if tt.wantErrDecode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrDecode.Error()) {
					t.Errorf(
						"decodeMASTERCARDPAYNOWPAYLATER() error = %v, wantErr %v",
						err,
						tt.wantErrDecode,
					)
				}

				return
			}
			if err != nil {
				t.Fatalf("decodeMASTERCARDPAYNOWPAYLATER() unexpected error = %v", err)
			}
			if decodedPin != tt.pin {
				t.Errorf("decodeMASTERCARDPAYNOWPAYLATER() got = %v, want %v", decodedPin, tt.pin)
			}
		})
	}
	t.Run("decodeMASTERCARDPAYNOWPAYLATER invalid format prefix", func(t *testing.T) {
		t.Parallel()
		panForZeroXOR := "0000000000000000"    // PAN part will be 0000000000000000.
		clearPinFieldHex := "141234FFFFFFFFFF" // Invalid prefix '1' (expected '2').
		pinBlockHex, _ := xorHexStrings(clearPinFieldHex, "0000000000000000")
		_, err := decodeMASTERCARDPAYNOWPAYLATER(pinBlockHex, panForZeroXOR)
		if err == nil || !strings.Contains(err.Error(), "invalid format prefix") {
			t.Errorf("decodeMASTERCARDPAYNOWPAYLATER() with invalid prefix error = %v", err)
		}
	})
}

func TestEncodeDecodeVISANEWPINONLY(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		newPin        string
		udkHex        string
		wantErrEncode error
		wantErrDecode error
	}{
		{name: "valid visa new pin only", newPin: "1234", udkHex: "0123456789ABCDEF"},
		{
			name:          "visa new pin only udk too short",
			newPin:        "1234",
			udkHex:        "1234567",
			wantErrEncode: errInvalidPanLength,
			wantErrDecode: errInvalidPanLength,
		}, // errInvalidPanLength for UDK issues.
	}
	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			encodedHex, err := encodeVISANEWPINONLY(tt.newPin, tt.udkHex)
			if tt.wantErrEncode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrEncode.Error()) {
					t.Errorf("encodeVISANEWPINONLY() error = %v, wantErr %v", err, tt.wantErrEncode)
				}
				// ...

				return
			}
			if err != nil {
				t.Fatalf("encodeVISANEWPINONLY() unexpected error = %v", err)
			}

			decodedPin, err := decodeVISANEWPINONLY(encodedHex, tt.udkHex)
			if tt.wantErrDecode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrDecode.Error()) {
					t.Errorf("decodeVISANEWPINONLY() error = %v, wantErr %v", err, tt.wantErrDecode)
				}

				return
			}
			if err != nil {
				t.Fatalf("decodeVISANEWPINONLY() unexpected error = %v", err)
			}
			if decodedPin != tt.newPin {
				t.Errorf("decodeVISANEWPINONLY() got = %v, want %v", decodedPin, tt.newPin)
			}
		})
	}
}

func TestEncodeDecodeVISANEWOLDIN(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name            string
		newPin          string
		oldPinAndUdkHex string // "OLDPIN|UDKHEX".
		wantErrEncode   error
		wantErrDecode   error
	}{
		{name: "valid visa new old in", newPin: "5678", oldPinAndUdkHex: "1234|0123456789ABCDEF"},
		{
			name:            "visa new old in invalid oldpinudk format",
			newPin:          "5678",
			oldPinAndUdkHex: "1234_01234567",
			wantErrEncode:   errInvalidPanLength,
			wantErrDecode:   errInvalidPanLength,
		},
		{
			name:            "visa new old in udk too short",
			newPin:          "5678",
			oldPinAndUdkHex: "1234|123456",
			wantErrEncode:   errInvalidPanLength,
			wantErrDecode:   errInvalidPanLength,
		},
		{
			name:            "visa new old in oldpin too short",
			newPin:          "5678",
			oldPinAndUdkHex: "123|01234567",
			wantErrEncode:   errInvalidPinLength,
			wantErrDecode:   errInvalidPinLength,
		},
	}
	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			encodedHex, err := encodeVISANEWOLDIN(tt.newPin, tt.oldPinAndUdkHex)
			if tt.wantErrEncode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrEncode.Error()) {
					t.Errorf("encodeVISANEWOLDIN() error = %v, wantErr %v", err, tt.wantErrEncode)
				}
				// ...

				return
			}
			if err != nil {
				t.Fatalf("encodeVISANEWOLDIN() unexpected error = %v", err)
			}

			decodedPin, err := decodeVISANEWOLDIN(encodedHex, tt.oldPinAndUdkHex)
			if tt.wantErrDecode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrDecode.Error()) {
					t.Errorf("decodeVISANEWOLDIN() error = %v, wantErr %v", err, tt.wantErrDecode)
				}

				return
			}
			if err != nil {
				t.Fatalf("decodeVISANEWOLDIN() unexpected error = %v", err)
			}
			if decodedPin != tt.newPin {
				t.Errorf("decodeVISANEWOLDIN() got = %v, want %v", decodedPin, tt.newPin)
			}
		})
	}
}

func TestNotImplementedFormats(t *testing.T) {
	t.Parallel()
	formats := []struct {
		name     string
		encodeFn func(pin, pan string) (string, error)
		decodeFn func(pinBlockHex, pan string) (string, error)
	}{
		{"ECI1", encodeECI1, decodeECI1},
		{"VISA2", encodeVISA2, decodeVISA2},
		{"VISA3", encodeVISA3, decodeVISA3},
		{"VISA4", encodeVISA4, decodeVISA4},
		{"NCR", encodeNCR, decodeNCR},
	}

	for _, f := range formats {
		f := f // capture range variable.
		t.Run(f.name+" encode", func(t *testing.T) {
			t.Parallel()
			_, err := f.encodeFn("1234", "dummy")
			if err == nil || !strings.Contains(err.Error(), errFormatNotImplemented.Error()) {
				t.Errorf("%s encodeFn error = %v, wantErr %v", f.name, err, errFormatNotImplemented)
			}
		})
		t.Run(f.name+" decode", func(t *testing.T) {
			t.Parallel()
			_, err := f.decodeFn("dummy", "dummy")
			if err == nil || !strings.Contains(err.Error(), errFormatNotImplemented.Error()) {
				t.Errorf("%s decodeFn error = %v, wantErr %v", f.name, err, errFormatNotImplemented)
			}
		})
	}
}

// Helper for testing XOR logic if needed, not directly part of public API to test here
// unless it's through the format functions.

func TestGet12PanDigits(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		pan      string
		fromLeft bool
		want     string
		wantErr  error
	}{
		{"left simple", "123456789012345", true, "123456789012", nil},
		{
			"right simple",
			"1234567890123",
			false,
			"123456789012",
			nil,
		}, // pan "123456789012" (len 12 after removing check '3').
		{"left with chars", "123-456-789-012-345", true, "123456789012", nil},
		{"right with chars", "123-456-789-012-3", false, "123456789012", nil},
		{"too short left", "12345", true, "", errInvalidPanLength},
		{"too short right", "12345", false, "", errInvalidPanLength},
		{
			"too short right after check",
			"12345678901",
			false,
			"",
			errInvalidPanLength,
		}, // 10 digits after removing check.
	}

	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := get12PanDigits(tt.pan, tt.fromLeft)
			if tt.wantErr != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr.Error()) {
					t.Errorf("get12PanDigits() error = %v, wantErr %v", err, tt.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("get12PanDigits() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("get12PanDigits() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestXorHexStrings(t *testing.T) {
	t.Parallel()
	// Test cases for xorHexStrings.
	tests := []struct {
		name    string
		s1      string
		s2      string
		want    string
		wantErr bool
	}{
		{"simple xor", "1111", "2222", "3333", false},
		{"xor with F", "F0F0", "0F0F", "FFFF", false},
		{"mismatched length", "11", "2222", "", true},
		{"invalid hex s1", "1G", "11", "", true},
		{"invalid hex s2", "11", "2G", "", true},
	}

	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := xorHexStrings(tt.s1, tt.s2)
			if (err != nil) != tt.wantErr {
				t.Errorf("xorHexStrings() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("xorHexStrings() = %v, want %v", got, tt.want)
			}
		})
	}
}
