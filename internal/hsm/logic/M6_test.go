package logic

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
)

// The test LMK provider returns a key "under LMK" as it is given, so the MAC
// key below is the clear key. The expected MACs were computed with OpenSSL's
// DES over the same key and message.
const (
	macTestKey     = "U0123456789ABCDEFFEDCBA9876543210"
	macTestMessage = "Now is the time for all "
	macRetail      = "A1C72E74EA3FA9B6" // ISO/IEC 9797-1 algorithm 3
	macTripleDES   = "93462A6DB9B4A4D1" // ISO/IEC 9797-1 algorithm 1, TDEA
)

// macHead builds the fields before the message: mode, input format, MAC size,
// algorithm, padding, key type and key.
func macHead(format, size, algorithm, padding byte, keyType string) string {
	return fmt.Sprintf("0%c%c%c%c%s%s", format, size, algorithm, padding, keyType, macTestKey)
}

// binaryMessage is the message length and the message, as binary input.
func binaryMessage(msg string) string {
	return fmt.Sprintf("%04X%s", len(msg), msg)
}

func TestExecuteM6(t *testing.T) {
	t.Parallel()

	hexMsg := strings.ToUpper(hex.EncodeToString([]byte(macTestMessage)))

	tests := []struct {
		name    string
		input   string
		want    string
		wantErr error
	}{
		{
			name:  "retail MAC, 16 hex, ZAK",
			input: macHead('0', '1', '3', '1', "008") + binaryMessage(macTestMessage),
			want:  "M700" + macRetail,
		},
		{
			name:  "retail MAC, 8 hex, TAK",
			input: macHead('0', '0', '3', '1', "003") + binaryMessage(macTestMessage),
			want:  "M700" + macRetail[:8],
		},
		{
			name:  "algorithm 1 with a double-length key is triple DES",
			input: macHead('0', '1', '1', '1', "008") + binaryMessage(macTestMessage),
			want:  "M700" + macTripleDES,
		},
		{
			name:  "hex input gives the same MAC",
			input: macHead('1', '1', '3', '1', "008") + fmt.Sprintf("%04X%s", len(hexMsg), hexMsg),
			want:  "M700" + macRetail,
		},
		{
			name:  "unpadded whole blocks",
			input: macHead('0', '1', '3', '0', "008") + binaryMessage(macTestMessage),
			want:  "M700" + macRetail,
		},
		{
			name:    "unpadded part block",
			input:   macHead('0', '1', '3', '0', "008") + binaryMessage("0800"),
			wantErr: errorcodes.Err06,
		},
		{
			name:    "multi-block mode",
			input:   "1" + macHead('0', '1', '3', '1', "008")[1:] + binaryMessage(macTestMessage),
			wantErr: errorcodes.Err02,
		},
		{
			name:    "invalid input format",
			input:   macHead('2', '1', '3', '1', "008") + binaryMessage(macTestMessage),
			wantErr: errorcodes.Err03,
		},
		{
			name:    "invalid algorithm",
			input:   macHead('0', '1', '5', '1', "008") + binaryMessage(macTestMessage),
			wantErr: errorcodes.Err04,
		},
		{
			name:    "not a MAC key",
			input:   macHead('0', '1', '3', '1', "001") + binaryMessage(macTestMessage),
			wantErr: errorcodes.Err05,
		},
		{
			name:    "invalid padding",
			input:   macHead('0', '1', '3', '7', "008") + binaryMessage(macTestMessage),
			wantErr: errorcodes.Err09,
		},
		{
			name:    "message length past the input",
			input:   macHead('0', '1', '3', '1', "008") + "00FF" + macTestMessage,
			wantErr: errorcodes.Err06,
		},
		{
			name:    "key parity error",
			input:   "00131008U00000000000000000000000000000000" + binaryMessage(macTestMessage),
			wantErr: errorcodes.Err10,
		},
		{
			name:    "short input",
			input:   "0013",
			wantErr: errorcodes.Err15,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp, err := ExecuteM6([]byte(tc.input))
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
