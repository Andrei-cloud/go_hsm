// nolint:all // test package
package pinblock

import (
	"strings"
	"testing"
)

func TestISO0(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		pin           string
		pan           string
		wantErrEncode error
		wantErrDecode error
	}{
		{
			name: "valid iso0",
			pin:  "1234",
			pan:  "1234567890123456",
		},
		{
			name: "valid iso0 longer pin",
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
		tt := tt // capture range variable
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			encoded, err := encodeISO0(tt.pin, tt.pan)
			if tt.wantErrEncode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrEncode.Error()) {
					t.Errorf("encodeISO0() error = %v, wantErr %v", err, tt.wantErrEncode)
				}
				return
			}
			if err != nil {
				t.Errorf("encodeISO0() unexpected error: %v", err)
				return
			}

			decoded, err := decodeISO0(encoded, tt.pan)
			if tt.wantErrDecode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrDecode.Error()) {
					t.Errorf("decodeISO0() error = %v, wantErr %v", err, tt.wantErrDecode)
				}
				return
			}
			if err != nil {
				t.Errorf("decodeISO0() unexpected error: %v", err)
				return
			}

			if decoded != tt.pin {
				t.Errorf("Round trip failed: got %v, want %v", decoded, tt.pin)
			}
		})
	}
}

func TestISO1(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		pin           string
		pan           string
		wantErrEncode error
		wantErrDecode error
	}{
		{
			name: "valid iso1",
			pin:  "1234",
			pan:  "1234567890123456",
		},
		{
			name: "valid iso1 longer pin",
			pin:  "123456789012",
			pan:  "1234567890123456",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			encoded, err := encodeISO1(tt.pin, tt.pan)
			if tt.wantErrEncode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrEncode.Error()) {
					t.Errorf("encodeISO1() error = %v, wantErr %v", err, tt.wantErrEncode)
				}
				return
			}
			if err != nil {
				t.Errorf("encodeISO1() unexpected error: %v", err)
				return
			}

			decoded, err := decodeISO1(encoded, tt.pan)
			if tt.wantErrDecode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrDecode.Error()) {
					t.Errorf("decodeISO1() error = %v, wantErr %v", err, tt.wantErrDecode)
				}
				return
			}
			if err != nil {
				t.Errorf("decodeISO1() unexpected error: %v", err)
				return
			}

			if decoded != tt.pin {
				t.Errorf("Round trip failed: got %v, want %v", decoded, tt.pin)
			}
		})
	}
}

func TestISO2(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		pin           string
		pan           string
		want          string
		wantErrEncode error
		wantErrDecode error
	}{
		{
			name: "valid iso2",
			pin:  "1234",
			pan:  "0000000000000",
			want: "241234FFFFFFFF",
		},
		{
			name: "valid iso2 longer pin",
			pin:  "123456789012",
			pan:  "0000000000000",
			want: "2C123456789012",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			encoded, err := encodeISO2(tt.pin, tt.pan)
			if tt.wantErrEncode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrEncode.Error()) {
					t.Errorf("encodeISO2() error = %v, wantErr %v", err, tt.wantErrEncode)
				}
				return
			}
			if err != nil {
				t.Errorf("encodeISO2() unexpected error: %v", err)
				return
			}

			if tt.want != "" && encoded != tt.want {
				t.Errorf("encodeISO2() = %v, want %v", encoded, tt.want)
			}

			decoded, err := decodeISO2(encoded, tt.pan)
			if tt.wantErrDecode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrDecode.Error()) {
					t.Errorf("decodeISO2() error = %v, wantErr %v", err, tt.wantErrDecode)
				}
				return
			}
			if err != nil {
				t.Errorf("decodeISO2() unexpected error: %v", err)
				return
			}

			if decoded != tt.pin {
				t.Errorf("Round trip failed: got %v, want %v", decoded, tt.pin)
			}
		})
	}
}

func TestISO3(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		pin           string
		pan           string
		wantErrEncode error
		wantErrDecode error
	}{
		{
			name: "valid iso3",
			pin:  "1234",
			pan:  "1234567890123456",
		},
		{
			name: "valid iso3 longer pin",
			pin:  "123456789012",
			pan:  "1234567890123456",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			encoded, err := encodeISO3(tt.pin, tt.pan)
			if tt.wantErrEncode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrEncode.Error()) {
					t.Errorf("encodeISO3() error = %v, wantErr %v", err, tt.wantErrEncode)
				}
				return
			}
			if err != nil {
				t.Errorf("encodeISO3() unexpected error: %v", err)
				return
			}

			decoded, err := decodeISO3(encoded, tt.pan)
			if tt.wantErrDecode != nil {
				if err == nil || !strings.Contains(err.Error(), tt.wantErrDecode.Error()) {
					t.Errorf("decodeISO3() error = %v, wantErr %v", err, tt.wantErrDecode)
				}
				return
			}
			if err != nil {
				t.Errorf("decodeISO3() unexpected error: %v", err)
				return
			}

			if decoded != tt.pin {
				t.Errorf("Round trip failed: got %v, want %v", decoded, tt.pin)
			}
		})
	}
}
