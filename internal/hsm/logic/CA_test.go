// filepath: internal/hsm/logic/CA_test.go
package logic

import (
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
)

func TestExecuteCA(t *testing.T) {
	t.Parallel()

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
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp, err := ExecuteCA(tc.input)
			if err != tc.expErr {
				t.Fatalf("%s: expected error %v, got %v", tc.name, tc.expErr, err)
			}
			if resp != nil {
				t.Fatalf("%s: expected nil response, got %v", tc.name, resp)
			}
		})
	}
}
