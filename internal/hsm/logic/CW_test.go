package logic

import (
	"bytes"
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
)

func TestExecuteCW(t *testing.T) {
	t.Parallel()

	// Initialize test LMK provider
	if err := SetupTestLMKProvider(); err != nil {
		t.Fatalf("Failed to setup test LMK provider: %v", err)
	}

	tests := []struct {
		name     string
		input    string
		want     string
		wantErr  bool
		wantCode errorcodes.HSMError
	}{
		{
			name:  "Valid CVV calculation with good key",
			input: "0123456789ABCDEFFEDCBA98765432104111111111111111;2412123000",
			want:  "CX00424",
		},
		{
			name:  "Valid CVV calculation with variant key",
			input: "U0123456789ABCDEFFEDCBA98765432104111111111111111;2412123000",
			want:  "CX00424",
		},
		{
			name:     "Invalid input length - too short for CVK",
			input:    "0123",
			wantErr:  true,
			wantCode: errorcodes.Err15,
		},
		{
			name:     "Invalid input length - too short for U CVK",
			input:    "U0123456789ABCDEF0123456789ABCDE",
			wantErr:  true,
			wantCode: errorcodes.Err15,
		},
		{
			name:     "Invalid CVK hex",
			input:    "Z123456789ABCDEF0123456789ABCDEF4111111111111111;2412123000",
			wantErr:  true,
			wantCode: errorcodes.Err15,
		},
		{
			name:     "Invalid CVK parity",
			input:    "AAAAAAAAAAAAAAAA00000000000000004111111111111111;2412123000",
			wantErr:  true,
			wantCode: errorcodes.Err10, // Source key parity error
		},
		{
			name:     "CVK not double length",
			input:    "0123456789ABCDEF4111111111111111;2412123000",
			wantErr:  true,
			wantCode: errorcodes.Err15,
		},
		{
			name:     "Missing PAN delimiter",
			input:    "0123456789ABCDEFFEDCBA987654321041111111111111112412123000",
			wantErr:  true,
			wantCode: errorcodes.Err15,
		},
		{
			name:     "Empty PAN",
			input:    "0123456789ABCDEFFEDCBA9876543210;2412123000",
			wantErr:  true,
			wantCode: errorcodes.Err15,
		},
		{
			name:     "PAN too short (12 digits)",
			input:    "0123456789ABCDEFFEDCBA9876543210123456789012;2412123000",
			wantErr:  true,
			wantCode: errorcodes.Err15,
		},
		{
			name:     "PAN too long (20 digits)",
			input:    "0123456789ABCDEFFEDCBA987654321012345678901234567890;2412123000",
			wantErr:  true,
			wantCode: errorcodes.Err15,
		},
		{
			name:     "Not enough data for expDate and servCode",
			input:    "0123456789ABCDEFFEDCBA98765432104111111111111111;241212",
			wantErr:  true,
			wantCode: errorcodes.Err15,
		},
		{
			name:     "Invalid CVKA hex format in key pair",
			input:    "INVALIDHEX0000000123456789ABCDEF4111111111111111;2412123000",
			wantErr:  true,
			wantCode: errorcodes.Err15,
		},
		{
			name:     "Invalid CVKB hex format in key pair",
			input:    "0123456789ABCDEFINVALIDHEX00000004111111111111111;2412123000",
			wantErr:  true,
			wantCode: errorcodes.Err15,
		},
		{
			name:     "Key pair with invalid CVKA parity",
			input:    "0000000000000000FEDCBA987654321F4111111111111111;2412123000",
			wantErr:  true,
			wantCode: errorcodes.Err10,
		},
		{
			name:     "Key pair with invalid CVKB parity",
			input:    "FEDCBA98765432100000000000000004111111111111111;2412123000",
			wantErr:  true,
			wantCode: errorcodes.Err10,
		},
		{
			name:  "Valid CVV with different PAN length",
			input: "0123456789ABCDEFFEDCBA98765432104111111111111;2412123000",
			want:  "CX00906",
		},
		{
			name:  "Valid CVV with maximum PAN length",
			input: "0123456789ABCDEFFEDCBA98765432104111111111111111111;2412123000",
			want:  "CX00145",
		},
		{
			name:  "Different expiry date and service code",
			input: "0123456789ABCDEFFEDCBA98765432104111111111111111;2501999",
			want:  "CX00790", // Different CVV expected due to different exp date and service code
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ExecuteCW([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Errorf("ExecuteCW() expected error %v, got nil", tt.wantCode)
					return
				}
				if err != tt.wantCode {
					t.Errorf("ExecuteCW() error = %v, want %v", err, tt.wantCode)
				}

				return
			}

			if err != nil {
				t.Errorf("ExecuteCW() unexpected error = %v", err)
				return
			}

			if !bytes.Equal(got, []byte(tt.want)) {
				t.Errorf("ExecuteCW() = %s, want %s", got, tt.want)
			}
		})
	}
}
