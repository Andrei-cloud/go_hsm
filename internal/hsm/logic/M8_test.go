package logic

import (
	"errors"
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
)

func TestExecuteM8(t *testing.T) {
	t.Parallel()

	wrong := "B1C72E74EA3FA9B6"

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{
			name:  "retail MAC holds",
			input: macHead('0', '1', '3', '1', "008") + binaryMessage(macTestMessage) + macRetail,
			want:  "M900",
		},
		{
			name:  "8-digit MAC holds",
			input: macHead('0', '0', '3', '1', "008") + binaryMessage(macTestMessage) + macRetail[:8],
			want:  "M900",
		},
		{
			name:  "algorithm 1 MAC holds",
			input: macHead('0', '1', '1', '1', "003") + binaryMessage(macTestMessage) + macTripleDES,
			want:  "M900",
		},
		{
			name:    "wrong MAC fails verification",
			input:   macHead('0', '1', '3', '1', "008") + binaryMessage(macTestMessage) + wrong,
			wantErr: errorcodes.Err01,
		},
		{
			name:    "MAC of a changed message fails verification",
			input:   macHead('0', '1', '3', '1', "008") + binaryMessage("Now is the time for all!") + macRetail,
			wantErr: errorcodes.Err01,
		},
		{
			name:    "missing MAC",
			input:   macHead('0', '1', '3', '1', "008") + binaryMessage(macTestMessage) + "A1C7",
			wantErr: errorcodes.Err15,
		},
		{
			name:    "MAC not hex",
			input:   macHead('0', '1', '3', '1', "008") + binaryMessage(macTestMessage) + "ZZC72E74EA3FA9B6",
			wantErr: errorcodes.Err15,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp, err := ExecuteM8([]byte(tc.input))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error %v, want %v", err, tc.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(resp) != tc.want {
				t.Fatalf("response %s, want %s", resp, tc.want)
			}
		})
	}
}
