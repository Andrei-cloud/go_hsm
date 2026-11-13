package logic

import (
	"errors"
	"strings"
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
)

func TestExecuteA8(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{
			name:  "double-length ZAK under ZMK",
			input: "008" + exchangeZMK + "U" + exchangeKey + "X",
			want:  "A900X" + exchangeKeyUnderZMK + exchangeKeyKCV,
		},
		{
			name:  "single-length key, no scheme tag in the response",
			input: "001FEDCBA98765432100123456789ABCDEFZ",
			want:  "A900ED39D950FA74BCC4D5D44F",
		},
		{
			name:    "Thales variant form under ZMK",
			input:   "008" + exchangeZMK + "U" + exchangeKey + "U",
			wantErr: errorcodes.Err26,
		},
		{
			name:    "scheme does not match the key length",
			input:   "008" + exchangeZMK + "U" + exchangeKey + "Y",
			wantErr: errorcodes.Err27,
		},
		{
			name:    "missing scheme under ZMK",
			input:   "008" + exchangeZMK + "U" + exchangeKey,
			wantErr: errorcodes.Err15,
		},
		{
			name:    "key parity error",
			input:   "008" + exchangeZMK + "U" + strings.Repeat("0", 32) + "X",
			wantErr: errorcodes.Err11,
		},
		{
			name:    "ZMK parity error",
			input:   "008U" + strings.Repeat("0", 32) + "U" + exchangeKey + "X",
			wantErr: errorcodes.Err10,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp, err := ExecuteA8([]byte(tc.input))
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
