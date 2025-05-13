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
			name:             "Short Input",
			input:            []byte{1, 2, 3},
			expectedResponse: "",
			expectedError:    errorcodes.Err15,
		},
		{
			name: "Invalid PVK Parity",
			input: []byte("U1A4D672DCA6CB3351A4D672DCA6CB335" + // TPK Good Parity.
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
				"U063A0E7C0F2124E56192A4510F395ED78AC91C79495A9FC31750CDFB0757D3B3CB4EBC0180DFED6E0134551380493715986",
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
