// nolint:all // test package
package pinblock

import (
	"strings"
	"testing"
)

func TestVISA1(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		pin           string
		pan           string
		wantErrEncode error
		wantErrDecode error
	}{
		{
			name: "valid visa1",
			pin:  "1234",
			pan:  "1234567890123456",
		},
		{
			name: "valid visa1 longer pin",
			pin:  "123456789012",
			pan:  "1234567890123456",
		},
		{
			name:          "missing pan",
			pin:           "1234",
			pan:           "",
			wantErrEncode: errPanRequired,
			wantErrDecode: errPanRequired,
		},
		{
			name:          "short pan",
			pin:           "1234",
			pan:           "123456789012",
			wantErrEncode: errInvalidPanLength,
			wantErrDecode: errInvalidPanLength,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			encoded, err := encodeVISA1(tt.pin, tt.pan)
			if tt.wantErrEncode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrEncode.Error()) {
					t.Errorf("encodeVISA1() error = %v, wantErr %v", err, tt.wantErrEncode)
				}

				return
			}
			if err != nil {
				t.Errorf("encodeVISA1() unexpected error: %v", err)
				return
			}

			decoded, err := decodeVISA1(encoded, tt.pan)
			if tt.wantErrDecode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrDecode.Error()) {
					t.Errorf("decodeVISA1() error = %v, wantErr %v", err, tt.wantErrDecode)
				}

				return
			}
			if err != nil {
				t.Errorf("decodeVISA1() unexpected error: %v", err)
				return
			}

			if decoded != tt.pin {
				t.Errorf("Round trip failed: got %v, want %v", decoded, tt.pin)
			}
		})
	}
}

func TestVISANEWPINONLY(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		pin           string
		udkHex        string
		wantErrEncode error
		wantErrDecode error
	}{
		{
			name:   "valid visa new pin only",
			pin:    "1234",
			udkHex: "0123456789ABCDEF",
		},
		{
			name:   "valid visa new pin only longer pin",
			pin:    "123456789012",
			udkHex: "0123456789ABCDEF",
		},
		{
			name:          "invalid udk hex length",
			pin:           "1234",
			udkHex:        "1234",
			wantErrEncode: errInvalidPanLength,
			wantErrDecode: errInvalidPanLength,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			encoded, err := encodeVISANEWPINONLY(tt.pin, tt.udkHex)
			if tt.wantErrEncode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrEncode.Error()) {
					t.Errorf("encodeVISANEWPINONLY() error = %v, wantErr %v", err, tt.wantErrEncode)
				}
				return
			}
			if err != nil {
				t.Errorf("encodeVISANEWPINONLY() unexpected error: %v", err)
				return
			}

			decoded, err := decodeVISANEWPINONLY(encoded, tt.udkHex)
			if tt.wantErrDecode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrDecode.Error()) {
					t.Errorf("decodeVISANEWPINONLY() error = %v, wantErr %v", err, tt.wantErrDecode)
				}
				return
			}
			if err != nil {
				t.Errorf("decodeVISANEWPINONLY() unexpected error: %v", err)
				return
			}

			if decoded != tt.pin {
				t.Errorf("Round trip failed: got %v, want %v", decoded, tt.pin)
			}
		})
	}
}

func TestVISANEWOLDIN(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		newPin        string
		oldPinUdkHex  string
		wantErrEncode error
		wantErrDecode error
	}{
		{
			name:         "valid visa new old pin",
			newPin:       "1234",
			oldPinUdkHex: "5678|0123456789ABCDEF",
		},
		{
			name:         "valid visa new old pin longer",
			newPin:       "123456789012",
			oldPinUdkHex: "5678|0123456789ABCDEF",
		},
		{
			name:          "invalid format - missing separator",
			newPin:        "1234",
			oldPinUdkHex:  "1234",
			wantErrEncode: errInvalidPanLength,
			wantErrDecode: errInvalidPanLength,
		},
		{
			name:          "invalid old pin length",
			newPin:        "1234",
			oldPinUdkHex:  "12|0123456789ABCDEF",
			wantErrEncode: errInvalidPinLength,
			wantErrDecode: errInvalidPinLength,
		},
		{
			name:          "invalid udk hex length",
			newPin:        "1234",
			oldPinUdkHex:  "1234|1234",
			wantErrEncode: errInvalidPanLength,
			wantErrDecode: errInvalidPanLength,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			encoded, err := encodeVISANEWOLDIN(tt.newPin, tt.oldPinUdkHex)
			if tt.wantErrEncode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrEncode.Error()) {
					t.Errorf("encodeVISANEWOLDIN() error = %v, wantErr %v", err, tt.wantErrEncode)
				}
				return
			}
			if err != nil {
				t.Errorf("encodeVISANEWOLDIN() unexpected error: %v", err)
				return
			}

			decoded, err := decodeVISANEWOLDIN(encoded, tt.oldPinUdkHex)
			if tt.wantErrDecode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrDecode.Error()) {
					t.Errorf("decodeVISANEWOLDIN() error = %v, wantErr %v", err, tt.wantErrDecode)
				}
				return
			}
			if err != nil {
				t.Errorf("decodeVISANEWOLDIN() unexpected error: %v", err)
				return
			}

			if decoded != tt.newPin {
				t.Errorf("Round trip failed: got %v, want %v", decoded, tt.newPin)
			}
		})
	}
}
