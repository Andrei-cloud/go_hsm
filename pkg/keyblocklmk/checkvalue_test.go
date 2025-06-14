package keyblocklmk_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/andrei-cloud/go_hsm/pkg/keyblocklmk"
)

// TestCalculateCMACCheckValue verifies the CMAC-based AES key check value calculation.
func TestCalculateCMACCheckValue(t *testing.T) {
	t.Parallel()

	expectedCheckValueHexDefaultLMK := "DB3FB663EE8D2B66"
	expectedCheckValueDefaultLMK, err := hex.DecodeString(expectedCheckValueHexDefaultLMK)
	if err != nil {
		t.Fatalf("failed to decode expected check value hex for DefaultTestAESLMK: %v", err)
	}

	testCases := []struct {
		name        string
		key         []byte
		want        []byte
		wantErr     bool
		expectedErr string
	}{
		{
			name:    "valid DefaultTestAESLMK (32 bytes)",
			key:     keyblocklmk.DefaultTestAESLMK,
			want:    expectedCheckValueDefaultLMK,
			wantErr: false,
		},
		{
			name:        "nil key",
			key:         nil,
			wantErr:     true,
			expectedErr: "failed to compute CMAC for check value: aes cipher init failed: crypto/aes: invalid key size 0",
		},
		{
			name:        "short key (8 bytes)",
			key:         []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			wantErr:     true,
			expectedErr: "failed to compute CMAC for check value: aes cipher init failed: crypto/aes: invalid key size 8",
		},
		{
			name:        "invalid key size (10 bytes)",
			key:         []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a},
			wantErr:     true,
			expectedErr: "failed to compute CMAC for check value: aes cipher init failed: crypto/aes: invalid key size 10",
		},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := keyblocklmk.CalculateCMACCheckValue(tc.key)

			if tc.wantErr {
				if err == nil {
					t.Errorf("CalculateCMACCheckValue() error = nil, wantErr %v", tc.wantErr)

					return
				}
				// Check if the error message matches the expected one.
				if tc.expectedErr != "" && err.Error() != tc.expectedErr {
					t.Errorf(
						"CalculateCMACCheckValue() error = %q, want %q",
						err.Error(),
						tc.expectedErr,
					)
				}

				return
			}
			if err != nil {
				t.Errorf("CalculateCMACCheckValue() unexpected error = %v", err)

				return
			}

			if !bytes.Equal(got, tc.want) {
				t.Errorf("CalculateCMACCheckValue() = %X, want %X", got, tc.want)
			}
		})
	}
}
