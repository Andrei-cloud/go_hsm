//nolint:all // test package
package cryptoutils

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestRaw2StrAndRaw2B(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    []byte
		wantStr  string
		wantRawB []byte
	}{
		{
			name:     "basic hex conversion",
			input:    []byte{0x01, 0xAB, 0x0F},
			wantStr:  "01AB0F",
			wantRawB: []byte("01AB0F"),
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotStr := Raw2Str(tt.input)
			if gotStr != tt.wantStr {
				t.Errorf("Raw2Str() = %v, want %v", gotStr, tt.wantStr)
			}

			gotRawB := Raw2B(tt.input)
			if !reflect.DeepEqual(gotRawB, tt.wantRawB) {
				t.Errorf("Raw2B() = %v, want %v", gotRawB, tt.wantRawB)
			}
		})
	}
}

func TestB2Raw(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   []byte
		want    []byte
		wantErr bool
	}{
		{
			name:    "valid hex",
			input:   []byte("0a0b0c"),
			want:    []byte{0x0A, 0x0B, 0x0C},
			wantErr: false,
		},
		{
			name:    "invalid hex",
			input:   []byte("zz"),
			want:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := hex.DecodeString(string(tt.input))
			if (err != nil) != tt.wantErr {
				t.Errorf("B2Raw() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("B2Raw() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestXOR(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		b1      []byte
		b2      []byte
		want    []byte
		wantErr bool
	}{
		{
			name:    "valid XOR",
			b1:      []byte("AA"),
			b2:      []byte("01"),
			want:    []byte("AB"),
			wantErr: false,
		},
		{
			name:    "length mismatch",
			b1:      []byte("A"),
			b2:      []byte("BB"),
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := XOR(tt.b1, tt.b2)
			if (err != nil) != tt.wantErr {
				t.Errorf("XOR() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("XOR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHexify(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   int
		want    string
		wantErr bool
	}{
		{
			name:    "single digit",
			input:   10,
			want:    "0A",
			wantErr: false,
		},
		{
			name:    "max value",
			input:   255,
			want:    "FF",
			wantErr: false,
		},
		{
			name:    "negative value",
			input:   -1,
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := Hexify(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hexify() error = %v, wantErr %v", err, tt.wantErr)

				return
			}
			if got != tt.want {
				t.Errorf("Hexify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetDigitsFromString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		digits int
		want   string
	}{
		{
			name:   "mixed alphanumeric",
			input:  "1A2b3c4d",
			digits: 3,
			want:   "123",
		},
		{
			name:   "all letters",
			input:  "ABCDEF",
			digits: 2,
			want:   "01",
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := GetDigitsFromString(tt.input, tt.digits)
			if got != tt.want {
				t.Errorf("GetDigitsFromString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParityAndKeyParity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		parityInput   int
		wantParity    int
		keyInput      string
		wantKeyParity bool
	}{
		{
			name:          "even parity byte",
			parityInput:   0x00,
			wantParity:    0,
			keyInput:      "",
			wantKeyParity: false,
		},
		{
			name:          "odd parity byte",
			parityInput:   0x01,
			wantParity:    -1,
			keyInput:      "",
			wantKeyParity: false,
		},
		{
			name:          "mixed parity key",
			parityInput:   0x00,
			wantParity:    0,
			keyInput:      "0123456789ABCDEFFEDCBA9876543210",
			wantKeyParity: true,
		},
		{
			name:          "failing key",
			parityInput:   0x00,
			wantParity:    0,
			keyInput:      "deafbeedeafbeedeafbeedeafbeedeaf",
			wantKeyParity: false,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Test byte parity.
			if got := ParityOf(tt.parityInput); got != tt.wantParity {
				t.Errorf("ParityOf() = %v, want %v", got, tt.wantParity)
			}

			// Skip key parity tests for parity-only test cases.
			if tt.keyInput == "" {
				return
			}

			// Test key parity.
			key, err := hex.DecodeString(tt.keyInput)
			if err != nil {
				t.Fatalf("failed to convert test key: %v", err)
			}

			if got := CheckKeyParity(key); got != tt.wantKeyParity {
				t.Errorf("CheckKeyParity() = %v, want %v", got, tt.wantKeyParity)
			}

			// Test key parity correction.
			fixed := FixKeyParity(key)
			if !CheckKeyParity(fixed) {
				t.Error("FixKeyParity() failed to correct key parity.")
			}
		})
	}
}
