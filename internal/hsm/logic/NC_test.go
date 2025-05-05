package logic

import (
	"encoding/hex"
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
)

func mockDecryptUnderLMKForNC(input []byte) ([]byte, error) {
	// Simulate decryption but return predictable bytes.
	result := make([]byte, len(input))
	for i := range result {
		result[i] = byte(i + 1)
	}

	return result, nil
}

func mockEncryptUnderLMKForNC(input []byte) ([]byte, error) {
	// For KCV calculation, return predictable bytes.
	result := make([]byte, len(input))
	for i := range result {
		result[i] = byte(i + 1)
	}

	return result, nil
}

func mockLogFnNC(_ string) {}

func TestExecuteNC(t *testing.T) {
	t.Parallel()

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
			input:            []byte{1, 2, 3},
			mockDecrypt:      mockDecryptUnderLMKForNC,
			mockEncrypt:      mockEncryptUnderLMKForNC,
			mockLog:          mockLogFnNC,
			expectedResponse: "",
			expectedError:    errorcodes.Err15, // Assuming short input is an error.
		},
		{
			name:             "Successful",
			input:            []byte("0007-E000"), // 9 bytes long.
			mockDecrypt:      mockDecryptUnderLMKForNC,
			mockEncrypt:      mockEncryptUnderLMKForNC,
			mockLog:          mockLogFnNC,
			expectedResponse: "ND00" + "0102030405060708090a0b0c0d0e0f10" + "0007-E000", // Placeholder KCV.
			expectedError:    nil,
		},
	}

	// --- Run Tests. ---
	for _, tc := range testCases {
		tc := tc // Capture range variable.
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp, err := ExecuteNC(tc.input, tc.mockDecrypt, tc.mockEncrypt, tc.mockLog)

			if err != tc.expectedError {
				t.Errorf("expected error %v, got %v", tc.expectedError, err)
			}

			// Specific checks for successful case
			if tc.expectedError == nil {
				// Response format: ND00 + KCV(16 hex chars) + firmware version
				expectedLen := 4 + 16 + len(tc.input)
				if len(resp) != expectedLen {
					t.Errorf("expected response length %d, got %d", expectedLen, len(resp))
				}
				if string(resp[:4]) != "ND00" {
					t.Errorf("expected ND00 prefix, got %s", string(resp[:4]))
				}
				kcv := resp[4:20]
				if _, hexErr := hex.DecodeString(string(kcv)); hexErr != nil {
					t.Errorf("invalid KCV hex format: %v", hexErr)
				}
				if string(resp[20:]) != string(tc.input) {
					t.Errorf(
						"expected firmware version %s, got %s",
						string(tc.input),
						string(resp[20:]),
					)
				}
			}
		})
	}
}
