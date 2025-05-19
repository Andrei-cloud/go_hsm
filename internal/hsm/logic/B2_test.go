package logic

import (
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
)

func TestExecuteB2(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		input            []byte
		expectedResponse []byte
		expectedError    error
	}{
		{
			name:             "Short Input",
			input:            []byte{1},
			expectedResponse: nil,
			expectedError:    errorcodes.Err15,
		},
		// TODO: Add more test cases
	}

	for _, tc := range testCases {
		tc := tc // Capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp, err := ExecuteB2(tc.input)

			if err != tc.expectedError {
				t.Errorf("expected error %v, got %v", tc.expectedError, err)
			}

			if err == nil {
				if string(resp[:4]) != "B300" {
					t.Errorf("expected prefix B300, got %s", string(resp[:4]))
				}
			}
		})
	}
}
