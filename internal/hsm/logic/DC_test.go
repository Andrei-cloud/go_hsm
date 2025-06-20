package logic

import (
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/stretchr/testify/assert"
)

func TestExecuteDC(t *testing.T) {
	t.Parallel()

	// Initialize the test LMK provider.
	if err := SetupTestLMKProvider(); err != nil {
		t.Fatalf("Failed to setup test LMK provider: %v", err)
	}

	// Valid test keys with proper DES parity.
	const (
		validTPK     = "U0123456789ABCDEFFEDCBA9876543210"   // Good parity double-length TPK
		validPVK     = "U0123456789ABCDEF0123456789ABCDEF"   // Good parity double-length PVK
		badParityKey = "U0000000000000000000000000000000000" // Bad parity key
	)

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{
			name:    "Short input",
			input:   "123",
			want:    "",
			wantErr: errorcodes.Err15,
		},
		{
			name:    "Invalid TPK scheme T",
			input:   "T1A4D672DCA6CB3351A4D672DCA6CB335" + validPVK + "0123456789ABCDEF01123456789012" + "1" + "1234",
			want:    "",
			wantErr: errorcodes.Err15,
		},
		{
			name:    "Invalid PVK single length with U scheme",
			input:   validTPK + "U0123456789ABCDEF" + "0123456789ABCDEF01123456789012" + "1" + "1234",
			want:    "",
			wantErr: errorcodes.Err15,
		},
		{
			name:    "Invalid PIN block format",
			input:   validTPK + validPVK + "0123456789ABCDEF99123456789012" + "1" + "1234",
			want:    "",
			wantErr: errorcodes.Err23,
		},
		{
			name:    "Valid format but verification should fail",
			input:   validTPK + validPVK + "CB4EBC0180DFED6E01345513804937" + "1" + "2678",
			want:    "",
			wantErr: errorcodes.Err01,
		},
		{
			name:    "Valid format verification should pass",
			input:   validTPK + validPVK + "CB4EBC0180DFED6E01345513804937" + "1" + "2677",
			want:    "DD00",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ExecuteDC([]byte(tt.input))
			if tt.wantErr != nil {
				assert.Equal(t, tt.wantErr, err)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}
