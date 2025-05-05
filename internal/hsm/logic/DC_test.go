package logic

import (
	"strings"
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/internal/hsm" // Added for default LMK.
)

// mockDecryptUnderLMKGoodParity simulates decryption returning a key with good parity.
func mockDecryptUnderLMKGoodParity(input []byte) ([]byte, error) {
	// Return a key known to have good parity (e.g., all 0xAA).
	result := make([]byte, len(input))
	for i := range result {
		result[i] = 0xAA // byte with odd parity.
	}

	return result, nil
}

func mockEncryptUnderLMKDC(input []byte) ([]byte, error) {
	// Simulate encryption similarly to decrypt.
	result := make([]byte, len(input))
	for i := range result {
		result[i] = 0xAA // byte with odd parity.
	}

	return result, nil
}

// mockDecryptWithDefaultLMK simulates decryption using the default LMK.
func mockDecryptWithDefaultLMK(input []byte) ([]byte, error) {
	// Use the default LMK from the HSM package.
	defaultLMKHex := "0123456789ABCDEFFEDCBA9876543210"
	hsmSvc, err := hsm.NewHSM(defaultLMKHex, "") // Firmware version not needed here.
	if err != nil {
		return nil, err
	}

	return hsmSvc.DecryptUnderLMK(input)
}

// mockEncryptWithDefaultLMK simulates encryption using the default LMK.
func mockEncryptWithDefaultLMK(input []byte) ([]byte, error) {
	// Use the default LMK from the HSM package.
	defaultLMKHex := "0123456789ABCDEFFEDCBA9876543210"
	hsmSvc, err := hsm.NewHSM(defaultLMKHex, "") // Firmware version not needed here.
	if err != nil {
		return nil, err
	}

	return hsmSvc.EncryptUnderLMK(input)
}

func mockLogFnDC(_ string) {}

func TestExecuteDC(t *testing.T) {
	t.Parallel()
	// Custom mock decrypt for the parity error case.
	testCases := []struct {
		name             string
		input            []byte
		mockDecrypt      func([]byte) ([]byte, error)
		mockEncrypt      func([]byte) ([]byte, error)
		mockLog          func(string)
		expectedResponse string
		expectedError    error
	}{
		{
			name:             "Short Input",
			input:            []byte{1, 2, 3},
			mockDecrypt:      mockDecryptUnderLMKGoodParity,
			mockEncrypt:      mockEncryptUnderLMKDC,
			mockLog:          mockLogFnDC,
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
			mockDecrypt:      mockDecryptWithDefaultLMK,
			mockEncrypt:      mockEncryptUnderLMKDC,
			mockLog:          mockLogFnDC,
			expectedResponse: "",
			expectedError:    errorcodes.Err11,
		},
		{
			name: "Successful Verification with Default LMK",
			input: []byte(
				"U1A4D672DCA6CB3351A4D672DCA6CB3351A4D672DCA6CB3351A4D672DCA6CB33568D267B408C2D4D90134551380493716469",
			),
			mockDecrypt:      mockDecryptWithDefaultLMK, // Use default LMK mock.
			mockEncrypt:      mockEncryptWithDefaultLMK, // Use default LMK mock.
			mockLog:          mockLogFnDC,
			expectedResponse: "DD" + errorcodes.Err00.CodeOnly(),
			expectedError:    nil,
		},
	}

	// --- Run Tests. ---
	for _, tc := range testCases {
		tc := tc // Capture range variable.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp, err := ExecuteDC(
				tc.input,
				tc.mockDecrypt,
				tc.mockEncrypt,
				tc.mockLog,
			)

			if err != tc.expectedError {
				t.Errorf("expected error %v, got %v", tc.expectedError, err)
			}

			if string(resp) != tc.expectedResponse {
				t.Errorf("expected response %q, got %q", tc.expectedResponse, string(resp))
			}
		})
	}
}
