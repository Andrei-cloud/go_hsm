package logic

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
)

// The test LMK provider returns a key "under LMK" as given, so the ZMK below
// is the clear ZMK. The key under the ZMK was computed with OpenSSL's DES
// (des-ede-ecb): 0123456789ABCDEFFEDCBA9876543210 under the ZMK.
const (
	exchangeZMK         = "UFEDCBA98765432100123456789ABCDEF"
	exchangeKey         = "0123456789ABCDEFFEDCBA9876543210"
	exchangeKeyUnderZMK = "E02E4FD4DC850651E5B298D235934CCA"
	exchangeKeyKCV      = "08D7B4"
)

// underTestLMK is clearHex as the test LMK provider encrypts it.
func underTestLMK(t *testing.T, clearHex string) string {
	t.Helper()

	clearKey, _ := hex.DecodeString(clearHex)
	testKey, _ := hex.DecodeString(testLMKKeyHex)

	encrypted, err := testEncryptWithLMK(clearKey, testKey)
	if err != nil {
		t.Fatal(err)
	}

	return strings.ToUpper(hex.EncodeToString(encrypted))
}

func TestExecuteA6(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{
			name:  "double-length ZAK under ZMK",
			input: "008" + exchangeZMK + "X" + exchangeKeyUnderZMK + "U",
			want:  "A700U" + underTestLMK(t, exchangeKey) + exchangeKeyKCV,
		},
		{
			name:  "single-length key without a scheme tag",
			input: "001FEDCBA9876543210ED39D950FA74BCC4Z",
			want:  "A700" + underTestLMK(t, "0123456789ABCDEF") + "D5D44F",
		},
		{
			name:  "parity error is a warning with the key",
			input: "008" + exchangeZMK + "X" + "E02E4FD4DC850651E5B298D235934CCB" + "U",
		},
		{
			name:    "Thales variant form under ZMK",
			input:   "008" + exchangeZMK + "U" + exchangeKeyUnderZMK + "U",
			wantErr: errorcodes.Err26,
		},
		{
			name:    "key length does not match the LMK scheme",
			input:   "008" + exchangeZMK + "X" + exchangeKeyUnderZMK + "T",
			wantErr: errorcodes.Err27,
		},
		{
			name:    "invalid LMK scheme",
			input:   "008" + exchangeZMK + "X" + exchangeKeyUnderZMK + "Q",
			wantErr: errorcodes.Err26,
		},
		{
			name:    "missing LMK scheme",
			input:   "008" + exchangeZMK + "X" + exchangeKeyUnderZMK,
			wantErr: errorcodes.Err15,
		},
		{
			name:    "all-zero key",
			input:   "008" + exchangeZMK + "X" + strings.Repeat("0", 32) + "U",
			wantErr: errorcodes.Err11,
		},
		{
			name:    "ZMK parity error",
			input:   "008U" + strings.Repeat("0", 32) + "X" + exchangeKeyUnderZMK + "U",
			wantErr: errorcodes.Err10,
		},
		{
			name:    "short input",
			input:   "00",
			wantErr: errorcodes.Err15,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp, err := ExecuteA6([]byte(tc.input))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error %v, want %v", err, tc.wantErr)
				}

				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.want == "" {
				if !strings.HasPrefix(string(resp), "A701U") || len(resp) != 4+33+6 {
					t.Fatalf("response %s, want a parity warning with the key", resp)
				}

				return
			}
			if string(resp) != tc.want {
				t.Fatalf("response %s, want %s", resp, tc.want)
			}
		})
	}
}
