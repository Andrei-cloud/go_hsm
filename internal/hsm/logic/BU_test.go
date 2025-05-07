package logic

import (
	"encoding/hex" // Import hex package.
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/internal/hsm"
)

// Mock functions that simulate actual HSM encryption/decryption.
func mockDecryptUnderLMKForBU(input []byte) ([]byte, error) {
	// Simulate decryption by using a test key with good parity.
	result := make([]byte, len(input))
	for i := range result {
		result[i] = 0xAA // byte with odd parity.
	}

	return result, nil
}

func mockEncryptUnderLMKForBU(input []byte) ([]byte, error) {
	// Simulate encryption similarly to decrypt.
	result := make([]byte, len(input))
	for i := range result {
		result[i] = 0xAA // byte with odd parity.
	}

	return result, nil
}

func mockLogFnBU(_ string) {}

func TestExecuteBU(t *testing.T) {
	t.Parallel()

	// --- Helper Data. ---
	goodKeyHex := "001U1A4D672DCA6CB3351FD1B02B237AF9AE"

	badKeyBytes := make([]byte, 16) // All zeros have even parity.
	badKeyHex := hex.EncodeToString(badKeyBytes)

	mockDecryptBadParity := func(_ []byte) ([]byte, error) {
		return badKeyBytes, nil
	}

	// --- Test Cases. ---
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
			input:            []byte{1, 2},
			mockDecrypt:      mockDecryptUnderLMKForBU,
			mockEncrypt:      mockEncryptUnderLMKForBU,
			mockLog:          mockLogFnBU,
			expectedResponse: "",
			expectedError:    errorcodes.Err15,
		},
		{
			name: "Invalid Key Scheme",
			input: append(
				[]byte{'0', '0', '0', 'X'},
				[]byte(goodKeyHex)...,
			),
			mockDecrypt:      mockDecryptUnderLMKForBU,
			mockEncrypt:      mockEncryptUnderLMKForBU,
			mockLog:          mockLogFnBU,
			expectedResponse: "",
			expectedError:    errorcodes.Err26,
		},
		{
			name: "Invalid Key Parity",
			input: append(
				[]byte{'0', '0', '0', 'U'},
				[]byte(badKeyHex)...,
			),
			mockDecrypt:      mockDecryptBadParity,
			mockEncrypt:      mockEncryptUnderLMKForBU,
			mockLog:          mockLogFnBU,
			expectedResponse: "",
			expectedError:    errorcodes.Err01,
		},
		{
			name:  "Successful with Actual HSM Decrypt",
			input: []byte(goodKeyHex),
			mockDecrypt: func(input []byte) ([]byte, error) {
				// Instantiate HSM and use its actual decrypt function.
				hsmInstance, err := hsm.NewHSM("0123456789ABCDEFFEDCBA9876543210", "0007-E000")
				if err != nil {
					return nil, err
				}

				return hsmInstance.DecryptUnderLMK(input)
			},
			mockEncrypt:      mockEncryptUnderLMKForBU,
			mockLog:          mockLogFnBU,
			expectedResponse: "BV00" + goodKeyHex,
			expectedError:    nil,
		},
	}

	// --- Run Tests. ---
	for _, tc := range testCases {
		tc := tc // Capture range variable.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp, err := ExecuteBU(tc.input, tc.mockDecrypt, tc.mockEncrypt, tc.mockLog)

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
