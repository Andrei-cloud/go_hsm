package logic

import (
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
			input:   "U0123456789ABCDEFFEDCBA9876543210" + "251" + "1234567890123456" + ";" + "2212" + "999",
			want:    "CZ00",
			wantErr: nil,
		},
		{
			name:    "Invalid CVV verification with U-prefixed CVK",
			input:   "U0123456789ABCDEFFEDCBA9876543210" + "999" + "1234567890123456" + ";" + "2212" + "999",
			wantErr: errorcodes.Err01,
		},
		{
			name:    "Too short input",
			input:   "31",
			want:    "",
			wantErr: errorcodes.Err15,
		},
		{
			name:    "Invalid PAN format (no delimiter)",
			input:   "U0123456789ABCDEFFEDCBA9876543210" + "123" + "1234567890123456",
			want:    "",
			wantErr: errorcodes.Err15,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ExecuteCY([]byte(tt.input))
			if tt.wantErr != nil {
				assert.Equal(t, tt.wantErr, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}
