package logic

import (
	"encoding/hex" // Import hex package.
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
)

func TestExecuteBU(t *testing.T) {
	t.Parallel()

	// --- Helper Data. ---
	goodKeyHex := "001U0123456789ABCDEFFEDCBA9876543210"

	badKeyBytes := make([]byte, 16) // All zeros have even parity.
	badKeyHex := hex.EncodeToString(badKeyBytes)

	// --- Test Cases. ---
	testCases := []struct {
		name             string
		input            []byte
		expectedResponse string
		expectedError    error
	}{
		{
			name:             "Short Input",
			input:            []byte{1, 2},
			expectedResponse: "",
			expectedError:    errorcodes.Err15,
		},
		{
			name: "Invalid Key Scheme",
			input: append(
				[]byte{'0', '0', '0', 'X'},
				[]byte(goodKeyHex)...,
			),
			expectedResponse: "",
			expectedError:    errorcodes.Err26,
		},
		{
			name: "Invalid Key Parity",
			input: append(
				[]byte{'0', '0', '0', 'U'},
				[]byte(badKeyHex)...,
			),
			expectedResponse: "",
			expectedError:    errorcodes.Err01,
		},
		{
			name:             "Successful with Actual HSM Decrypt",
			input:            []byte(goodKeyHex),
			expectedResponse: "BV00" + goodKeyHex,
			expectedError:    nil,
		},
	}

	// Initialize the test LMK provider.
	if err := SetupTestLMKProvider(); err != nil {
		t.Fatalf("Failed to setup test LMK provider: %v", err)
	}

	// --- Run Tests. ---
	for _, tc := range testCases {
		tc := tc // Capture range variable.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp, err := ExecuteBU(tc.input)

			if err != tc.expectedError {
				t.Errorf("expected error %v, got %v", tc.expectedError, err)
			}

			// Specific checks for successful case
			if tc.expectedError == nil {
				// Check response format: BV00 + 16 hex chars KCV
				if len(resp) != 20 {
					t.Errorf("expected response length 20, got %d", len(resp))
				}
				if string(resp[:4]) != "BV00" {
					t.Errorf("expected BV00 prefix, got %s", string(resp[:4]))
				}
				// Check KCV is valid hex
				kcv := resp[4:]
				if _, hexErr := hex.DecodeString(string(kcv)); hexErr != nil {
					t.Errorf("invalid KCV hex format: %v", hexErr)
				}
			}
		})
	}
}
