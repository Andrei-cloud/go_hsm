package logic

import (
	"encoding/hex"
	"testing"
)

func TestMain(m *testing.M) {
	err := SetupTestLMKProvider()
	if err != nil {
		panic("Failed to setup test LMK provider: " + err.Error())
	}
	m.Run()
}

func TestExecuteFA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		input      []byte
		expectErr  bool
		expectCode string // expected response code ("00" or "01"), empty if error expected
		checkKCV   bool   // whether to check KCV is valid hex
	}{
		{
			name:      "AllZeroZPK",
			input:     []byte("U0123456789ABCDEF0123456789ABCDEFU00000000000000000000000000000000"),
			expectErr: true,
		},
		{
			name: "Success",
			input: []byte(
				"U0123456789ABCDEFFEDCBA9876543210U1A4D672DCA6CB3351A4D672DCA6CB335",
			),
			expectErr:  false,
			expectCode: "00",
			checkKCV:   true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp, err := ExecuteFA(tc.input)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}

				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(resp) < 4 {
				t.Fatalf("response too short: %d", len(resp))
			}
			if tc.expectCode != "" && string(resp[2:4]) != tc.expectCode {
				t.Errorf("expected error code %s, got %s", tc.expectCode, string(resp[2:4]))
			}
			if tc.checkKCV {
				kcv := resp[len(resp)-6:]
				_, err = hex.DecodeString(string(kcv))
				if err != nil {
					t.Errorf("invalid KCV: %s", string(kcv))
				}
			}
		})
	}
}
