package logic

import (
	"encoding/hex" // Import hex package.
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
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
	goodKeyBytes := make([]byte, 16) // 16 bytes = 32 hex chars.
	for i := range goodKeyBytes {
		goodKeyBytes[i] = 0xAA // Good parity bytes.
	}
	goodKeyHex := hex.EncodeToString(goodKeyBytes)

	badKeyBytes := make([]byte, 16) // All zeros have even parity.
	badKeyHex := hex.EncodeToString(badKeyBytes)

	// --- Mock Functions. ---
	mockDecryptGoodParity := func(_ []byte) ([]byte, error) {
		return goodKeyBytes, nil
	}
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
				[]byte(goodKeyHex)...), // X is invalid.
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
				[]byte(badKeyHex)...), // Valid scheme U, bad key.
			mockDecrypt:      mockDecryptBadParity,
			mockEncrypt:      mockEncryptUnderLMKForBU,
			mockLog:          mockLogFnBU,
			expectedResponse: "",
			expectedError:    errorcodes.Err01,
		},
		{
			name: "Successful",
			input: append(
				[]byte{'0', '0', '0', 'U'},
				[]byte(goodKeyHex)...), // Valid scheme U, good key.
			mockDecrypt:      mockDecryptGoodParity,
			mockEncrypt:      mockEncryptUnderLMKForBU,
			mockLog:          mockLogFnBU,
			expectedResponse: "BV00" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", // Placeholder KCV.
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
