package logic

import (
	"encoding/hex"
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/stretchr/testify/assert"
)

func TestExecuteCY(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{
			name:    "Valid CVV verification with U-prefixed CVK",
			input:   "313233" + "U" + "11111111111111111111111111111111" + "1234567890123456" + "3B" + "2212" + "999",
			want:    "CZ00",
			wantErr: nil,
		},
		{
			name:    "Invalid CVV verification with U-prefixed CVK",
			input:   "999999" + "U" + "11111111111111111111111111111111" + "1234567890123456" + "3B" + "2212" + "999",
			want:    "CZ01",
			wantErr: nil,
		},
		{
			name:    "Valid CVV verification with paired single-length CVKs",
			input:   "313233" + "1111111111111111" + "2222222222222222" + "1234567890123456" + "3B" + "2212" + "999",
			want:    "CZ00",
			wantErr: nil,
		},
		{
			name:    "Too short input",
			input:   "31",
			want:    "",
			wantErr: errorcodes.Err15,
		},
		{
			name:    "Invalid PAN format (no delimiter)",
			input:   "313233" + "U" + "11111111111111111111111111111111" + "1234567890123456",
			want:    "",
			wantErr: errorcodes.Err15,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			input, err := hex.DecodeString(tt.input)
			if err != nil {
				t.Fatalf("failed to decode test input hex: %v", err)
			}

			got, err := ExecuteCY(input)
			if tt.wantErr != nil {
				assert.Equal(t, tt.wantErr, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}
