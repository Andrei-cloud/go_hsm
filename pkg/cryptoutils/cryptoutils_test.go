package cryptoutils

import (
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
				t.Errorf("Raw2Str() = %v, want %v.", gotStr, tt.wantStr)
			}

			gotRawB := Raw2B(tt.input)
			if !reflect.DeepEqual(gotRawB, tt.wantRawB) {
				t.Errorf("Raw2B() = %v, want %v.", gotRawB, tt.wantRawB)
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
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := B2Raw(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("B2Raw() error = %v, wantErr %v.", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("B2Raw() = %v, want %v.", got, tt.want)
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
				t.Errorf("XOR() error = %v, wantErr %v.", err, tt.wantErr)

				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("XOR() = %v, want %v.", got, tt.want)
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
				t.Errorf("Hexify() error = %v, wantErr %v.", err, tt.wantErr)

				return
			}
			if got != tt.want {
				t.Errorf("Hexify() = %v, want %v.", got, tt.want)
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
				t.Errorf("GetDigitsFromString() = %v, want %v.", got, tt.want)
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
				t.Errorf("ParityOf() = %v, want %v.", got, tt.wantParity)
			}

			// Skip key parity tests for parity-only test cases.
			if tt.keyInput == "" {
				return
			}

			// Test key parity.
			key, err := B2Raw([]byte(tt.keyInput))
			if err != nil {
				t.Fatalf("failed to convert test key: %v.", err)
			}

			if got := CheckKeyParity(key); got != tt.wantKeyParity {
				t.Errorf("CheckKeyParity() = %v, want %v.", got, tt.wantKeyParity)
			}

			// Test key parity correction.
			fixed := FixKeyParity(key)
			if !CheckKeyParity(fixed) {
				t.Error("FixKeyParity() failed to correct key parity.")
			}
		})
	}
}

func TestComputePINBlockFormat0(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pin     string
		pan     string
		want    int
		wantErr bool
	}{
		{
			name:    "valid pin and pan",
			pin:     "1234",
			pan:     "4000123412341234",
			want:    16,
			wantErr: false,
		},
		{
			name:    "empty pin",
			pin:     "",
			pan:     "1234",
			want:    0,
			wantErr: true,
		},
		{
			name:    "empty pan",
			pin:     "1234",
			pan:     "",
			want:    0,
			wantErr: true,
		},
		{
			name:    "pin too long",
			pin:     "12345678901234",
			pan:     "4000123412341234",
			want:    0,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ComputePINBlockFormat0(tt.pin, tt.pan)
			if (err != nil) != tt.wantErr {
				t.Errorf("ComputePINBlockFormat0() error = %v, wantErr %v.", err, tt.wantErr)

				return
			}
			if !tt.wantErr && len(got) != tt.want {
				t.Errorf("ComputePINBlockFormat0() length = %v, want %v.", len(got), tt.want)
			}

			// Verify PIN block can be decrypted
			if !tt.wantErr {
				pin, err := ExtractPINFormat0(got, tt.pan)
				if err != nil {
					t.Errorf("ExtractPINFormat0() error = %v.", err)
				}
				if string(pin) != tt.pin {
					t.Errorf("ExtractPINFormat0() = %v, want %v.", string(pin), tt.pin)
				}
			}
		})
	}
}

func TestExtractPINFormat0(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pinBlock string
		pan      string
		wantPin  string
		wantErr  bool
	}{
		{
			name:     "valid pin block",
			pinBlock: "041235DCBEDCBEDC", // Correct XORed PIN block hex.
			pan:      "4000123412341234",
			wantPin:  "1234",
			wantErr:  false,
		},
		{
			name:     "invalid pin block length",
			pinBlock: "0412", // Still invalid length.
			pan:      "4000123412341234",
			wantPin:  "",
			wantErr:  true,
		},
		{
			name: "invalid pin length indicator",
			// Calculate expected block for PIN field 0F1234FFFFFFFFFF
			// 0F 12 34 FF FF FF FF FF ^ 00 00 01 23 41 23 41 23 = 0F 12 35 DC BE DC BE DC
			pinBlock: "0F1235DCBEDCBEDC",
			pan:      "4000123412341234",
			wantPin:  "",
			wantErr:  true,
		},
		{
			name: "non-numeric pin",
			// Calculate expected block for PIN field 04AB34FFFFFFFFFF
			// 04 AB 34 FF FF FF FF FF ^ 00 00 01 23 41 23 41 23 = 04 AB 35 DC BE DC BE DC
			pinBlock: "04AB35DCBEDCBEDC",
			pan:      "4000123412341234",
			wantPin:  "",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Convert pinBlock hex string to byte array.
			pinBlockBytes, err := B2Raw([]byte(tt.pinBlock))
			if err != nil &&
				!tt.wantErr { // Allow B2Raw error if wantErr is true (e.g., invalid length).
				t.Fatalf("failed to convert pinBlock: %v.", err)
			}

			// Handle cases where B2Raw itself should fail (like invalid length).
			if err != nil && tt.wantErr {
				return // Expected error from B2Raw, test passes.
			}

			got, err := ExtractPINFormat0(pinBlockBytes, tt.pan)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractPINFormat0() error = %v, wantErr %v.", err, tt.wantErr)

				return
			}
			if !tt.wantErr && string(got) != tt.wantPin {
				t.Errorf("ExtractPINFormat0() = %v, want %v.", string(got), tt.wantPin)
			}
		})
	}
}
