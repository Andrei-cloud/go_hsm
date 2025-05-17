package logic

import (
	"bytes"
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
)

func TestExecuteCW(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		want     string
		wantErr  bool
		wantCode errorcodes.HSMError
	}{
		{
			name:  "Valid CVV calculation with good key",
			input: "0123456789ABCDEF0123456789ABCDEF4111111111111111;2412123000",
			want:  "CX00123",
		},
		{
			name:  "Valid CVV calculation with variant key",
			input: "U0123456789ABCDEF0123456789ABCDEF4111111111111111;2412123000",
			want:  "CX00123",
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
			input:    "000000000000000000000000000000004111111111111111;2412123000",
			wantErr:  true,
			wantCode: errorcodes.Err10, // Changed from Err01 to Err10.
		},
		{
			name:     "CVK not double length",
			input:    "0123456789ABCDEF4111111111111111;2412123000",
			wantErr:  true,
			wantCode: errorcodes.Err27,
		},
		{
			name:     "Missing PAN delimiter",
			input:    "0123456789ABCDEF0123456789ABCDEF41111111111111112412123000",
			wantErr:  true,
			wantCode: errorcodes.Err15,
		},
		{
			name:     "Empty PAN",
			input:    "0123456789ABCDEF0123456789ABCDEF;2412123000",
			wantErr:  true,
			wantCode: errorcodes.Err15,
		},
		{
			name:     "Not enough data for expDate and servCode",
			input:    "0123456789ABCDEF0123456789ABCDEF4111111111111111;241212",
			wantErr:  true,
			wantCode: errorcodes.Err15,
		},
		{
			name:     "GetVisaCVV internal error (e.g. bad PAN hex)",
			input:    "0123456789ABCDEF0123456789ABCDEFNOTHEX;2412123000",
			wantErr:  true,
			wantCode: errorcodes.Err42,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
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
