package logic

import (
	"strings"
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
)

func TestExecuteEC(t *testing.T) {
	t.Parallel()
	// Custom mock decrypt for the parity error case.
	testCases := []struct {
		name             string
		input            []byte
		expectedResponse string
		expectedError    error
	}{
		{
			name: "Invalid PVK Parity",
			input: []byte("U0123456789ABCDEFFEDCBA9876543210" + // TPK Good Parity.
				"U" + strings.Repeat("00", 16) + // PVK Bad Parity.
				strings.Repeat("00", 8) + // PIN Block.
				"01" + // Format Code.
				"123456789012" + // Account Number.
				"1" + // PVKI.
				"1234"), // PVV.
			expectedResponse: "",
			expectedError:    errorcodes.Err11,
		},
		{
			name: "Successful Verification with Default LMK",
			input: []byte(
				"U0123456789ABCDEFFEDCBA98765432100123456789ABCDEF0123456789ABCDEFCB4EBC0180DFED6E0134551380493712677",
			),
			expectedResponse: "ED" + errorcodes.Err00.CodeOnly(),
			expectedError:    nil,
		},
	}

	// --- Run Tests. ---
	for _, tc := range testCases {
		tc := tc // Capture range variable.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp, err := ExecuteEC(tc.input)

			if err != tc.expectedError {
				t.Errorf("expected error %v, got %v", tc.expectedError, err)
			}

			if string(resp) != tc.expectedResponse {
				t.Errorf("expected response %q, got %q", tc.expectedResponse, string(resp))
			}
		})
	}
}
