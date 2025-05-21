// filepath: internal/hsm/logic/CA_test.go
package logic

import (
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
)

func TestExecuteCA(t *testing.T) {
	t.Parallel()

	// Initialize the test LMK provider.
	if err := SetupTestLMKProvider(); err != nil {
		t.Fatalf("Failed to setup test LMK provider: %v", err)
	}

	// TODO: Replace these with actual valid test keys that are properly encrypted under the test LMK
	const (
		validTPK = "U1A4D672DCA6CB3351FD1B02B237AF9AE" // Replace with valid TPK
		validZPK = "U1A4D672DCA6CB3351FD1B02B237AF9AE" // Replace with valid ZPK
	)

	tests := []struct {
		name   string
		input  []byte
		expErr error
	}{
		{
			name:   "ShortInput",
			input:  []byte{0x00},
			expErr: errorcodes.Err15,
		},
		{
			name: "BadSrcScheme",
			// starts with invalid scheme 'Z'
			input:  append([]byte{'Z'}, make([]byte, 50)...),
			expErr: errorcodes.Err15,
		},
		{
			name:   "InvalidSourceKeyLength",
			input:  []byte("U1234"), // Too short key
			expErr: errorcodes.Err15,
		},
		{
			name:   "MissingDestinationKey",
			input:  []byte(validTPK),
			expErr: errorcodes.Err15,
		},
		{
			name:   "InvalidDestScheme",
			input:  append([]byte(validTPK), []byte("Z1234567890ABCDEF1234567890ABCDEF")...),
			expErr: errorcodes.Err15,
		},
		{
			name:   "ShortDestinationKey",
			input:  append([]byte(validTPK), []byte("U1234")...),
			expErr: errorcodes.Err15,
		},
		// TODO: Add success cases with valid TPK/ZPK pairs once keys are provided
		// {
		//     name: "ValidTranslation",
		//     input: append([]byte(validTPK), []byte(validZPK)...),
		//     expErr: nil,
		// },
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp, err := ExecuteCA(tc.input)
			if err != tc.expErr {
				t.Fatalf("%s: expected error %v, got %v", tc.name, tc.expErr, err)
			}
			if tc.expErr != nil && resp != nil {
				t.Fatalf("%s: expected nil response for error case, got %v", tc.name, resp)
			}
			// Response validation for success cases will be added with valid key pairs
		})
	}
}
