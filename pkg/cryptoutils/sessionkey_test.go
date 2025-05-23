//nolint:all // test package
package cryptoutils

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestDeriveSessionKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		km      string
		r       string
		want    string
		wantErr bool
	}{
		{
			name: "double-length DES key derivation",
			km:   "0123456789ABCDEFFEDCBA9876543210",
			r:    "001C000000000000",
			want: "E9FB384AF807B940FEDCEA613461B0C4",
		},
	}

	for _, tt := range tests {
		tt := tt // capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			kmBytes, err := hex.DecodeString(tt.km)
			if err != nil {
				t.Fatalf("Failed to decode km hex: %v", err)
			}

			rBytes, err := hex.DecodeString(tt.r)
			if err != nil {
				t.Fatalf("Failed to decode r hex: %v", err)
			}

			got, err := DeriveSessionKey(kmBytes, rBytes)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeriveSessionKey() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if !tt.wantErr {
				gotHex := strings.ToUpper(hex.EncodeToString(got))
				if gotHex != tt.want {
					t.Errorf("DeriveSessionKey() = %v, want %v", gotHex, tt.want)
				}
			}
		})
	}
}
