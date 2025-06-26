package logic

import (
	"encoding/hex"
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
)

func TestExecuteA0(t *testing.T) {
	t.Parallel()

	// Initialize the test LMK provider.
	if err := SetupTestLMKProvider(); err != nil {
		t.Fatalf("Failed to setup test LMK provider: %v", err)
	}

	testCases := []struct {
		name             string
		input            []byte
		expectedResponse []byte // Use byte slice for easier comparison.
		expectedError    error
	}{
		{
			name:             "Short Input",
			input:            []byte{1, 2, 3, 4},
			expectedResponse: nil,
			expectedError:    errorcodes.Err15,
		},
		{
			name: "Invalid Key Scheme",
			input: []byte{
				'0',
				'0',
				'0',
				'0',
				'K',
			}, // mode='0', keyType='000', keyScheme='X'.
			expectedResponse: nil,
			expectedError:    errorcodes.Err26,
		},
		{
			name: "No ZMK",
			input: []byte{
				'0',
				'0',
				'0',
				'0',
				'U',
			}, // mode='0', keyType='000', keyScheme='U'.
			expectedResponse: []byte(
				"A100U" + "0102030405060708090a0b0c0d0e0f10" + "010203040506",
			), // Placeholder response.
			expectedError: nil,
		},
		{
			name: "With ZMK",
			input: append(
				[]byte{
					'1',
					'0',
					'0',
					'0',
					'U',
					'T',
				}, // mode='1', keyType='000', keyScheme='U', ZMK scheme='T'.
				[]byte( // 48 hex chars for ZMK.
					"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
				)...),
			expectedResponse: []byte(
				"A100U" + "0102030405060708090a0b0c0d0e0f10" + "U" + "0102030405060708090a0b0c0d0e0f10" + "010203040506",
			), // Placeholder response.
			expectedError: nil,
		},
	}

	// --- Run Tests. ---
	for _, tc := range testCases {
		tc := tc // Capture range variable.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp, err := ExecuteA0(tc.input)

			if err != tc.expectedError {
				t.Errorf("expected error %v, got %v", tc.expectedError, err)
			}

			// Specific checks for successful cases
			if tc.expectedError == nil {
				switch tc.name {
				case "No ZMK":
					// Response format: 4 (A100) + 1('U') + 32(hex) + 6(KCV) = 43
					if len(resp) != 43 {
						t.Errorf("expected length 43, got %d", len(resp))
					}
					if string(resp[:4]) != "A100" {
						t.Errorf("expected prefix A100, got %q", resp[:4])
					}
					if resp[4] != 'U' {
						t.Errorf("expected 'U' at position 4, got %q", resp[4])
					}
					kcv := resp[len(resp)-6:]
					if _, hexErr := hex.DecodeString(string(kcv)); hexErr != nil {
						t.Errorf("expected valid 6-hex-digit KCV, got %q", kcv)
					}
				case "With ZMK":
					// Response format: 4 + 1 + 32 (under LMK) + 1 + 32 (under ZMK) + 6 (KCV) = 76
					if len(resp) != 76 {
						t.Errorf("expected length 76, got %d", len(resp))
					}
					if string(resp[:4]) != "A100" {
						t.Errorf("expected prefix A100, got %q", resp[:4])
					}
					if resp[37] != 'U' {
						t.Errorf("expected 'U' at position 37, got %q", resp[37])
					}
					kcv := resp[len(resp)-6:]
					if _, hexErr := hex.DecodeString(string(kcv)); hexErr != nil {
						t.Errorf("expected valid KCV hex format, got %q", kcv)
					}
				}
			}
		})
	}
}
