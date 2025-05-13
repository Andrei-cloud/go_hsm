package logic

import (
	"strings"
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	// Added for default LMK.
)

func TestExecuteDC(t *testing.T) {
	t.Parallel()

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
			name: "Invalid TPK Scheme - T Not Allowed",
			input: []byte("T" + strings.Repeat("A1", 16) + // TPK with T scheme
				"U" + strings.Repeat("B2", 16) + // PVK
				strings.Repeat("C3", 8) + // PIN Block
				"01" + // Format Code
				"123456789012" + // Account Number
				"1" + // PVKI
				"1234"), // PVV
			expectedResponse: "",
			expectedError:    errorcodes.Err15, // Should fail with invalid input
		},
		{
			name: "Invalid Single Length PVK with U Scheme",
			input: []byte("U" + strings.Repeat("A1", 16) + // TPK
				"U" + strings.Repeat("B2", 8) + // PVK (single length with U scheme)
				strings.Repeat("C3", 8) + // PIN Block
				"01" + // Format Code
				"123456789012" + // Account Number
				"1" + // PVKI
				"1234"), // PVV
			expectedResponse: "",
			expectedError:    errorcodes.Err27, // Should fail for non-double length PVK
		},
		{
			name: "Invalid PVK Parity - With U Scheme",
			input: []byte("U1A4D672DCA6CB3351A4D672DCA6CB335" + // TPK Good Parity
				"U" + strings.Repeat("00", 16) + // PVK Bad Parity
				strings.Repeat("00", 8) + // PIN Block
				"01" + // Format Code
				"123456789012" + // Account Number
				"1" + // PVKI
				"1234"), // PVV
			expectedResponse: "",
			expectedError:    errorcodes.Err11,
		},
		{
			name: "Invalid PVK Parity - Without Scheme (Part A)",
			input: []byte("U1A4D672DCA6CB3351A4D672DCA6CB335" + // TPK Good Parity
				strings.Repeat("00", 16) + // PVK A Bad Parity
				strings.Repeat("B2", 8) + // PVK B Good Parity
				strings.Repeat("00", 8) + // PIN Block
				"01" + // Format Code
				"123456789012" + // Account Number
				"1" + // PVKI
				"1234"), // PVV
			expectedResponse: "",
			expectedError:    errorcodes.Err11,
		},
		{
			name: "Invalid PIN Block Format",
			input: []byte("U1A4D672DCA6CB3351A4D672DCA6CB335" + // TPK
				"U1A4D672DCA6CB3351A4D672DCA6CB335" + // PVK
				strings.Repeat("C3", 8) + // PIN Block
				"99" + // Invalid Format Code
				"123456789012" + // Account Number
				"1" + // PVKI
				"1234"), // PVV
			expectedResponse: "",
			expectedError:    errorcodes.Err23,
		},
		{
			name: "PIN Verification Failure",
			input: []byte("U1A4D672DCA6CB3351A4D672DCA6CB335" + // TPK
				"U1A4D672DCA6CB3351A4D672DCA6CB335" + // PVK
				strings.Repeat("C3", 8) + // PIN Block
				"01" + // Format Code
				"123456789012" + // Account Number
				"1" + // PVKI
				"9999"), // Wrong PVV
			expectedResponse: "",
			expectedError:    errorcodes.Err01,
		},
		{
			name: "Single Length TPK Without Scheme",
			input: []byte(strings.Repeat("A1", 8) + // TPK (single length)
				"U1A4D672DCA6CB3351A4D672DCA6CB335" + // PVK
				strings.Repeat("C3", 8) + // PIN Block
				"01" + // Format Code
				"123456789012" + // Account Number
				"1" + // PVKI
				"1234"), // PVV
			expectedResponse: "",
			expectedError:    errorcodes.Err15, // Invalid input length for single TPK
		},
		{
			name: "Double Length PVK Without Scheme",
			input: []byte("U1A4D672DCA6CB3351A4D672DCA6CB335" + // TPK
				strings.Repeat(
					"B2",
					16,
				) + strings.Repeat("C3", 16) + // PVK (two single length keys)
				strings.Repeat("D4", 8) + // PIN Block
				"01" + // Format Code
				"123456789012" + // Account Number
				"1" + // PVKI
				"1234"), // PVV
			expectedResponse: "",
			expectedError:    errorcodes.Err15, // Should fail with invalid format
		},
		{
			name: "Successful Verification with Default LMK",
			input: []byte(
				"m",
			),
			expectedResponse: "DD" + errorcodes.Err00.CodeOnly(),
			expectedError:    nil,
		},
	}

	// --- Run Tests. ---
	for _, tc := range testCases {
		tc := tc // Capture range variable.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp, err := ExecuteDC(tc.input)

			if err != tc.expectedError {
				t.Errorf("expected error %v, got %v", tc.expectedError, err)
			}

			if string(resp) != tc.expectedResponse {
				t.Errorf("expected response %q, got %q", tc.expectedResponse, string(resp))
			}
		})
	}
}
