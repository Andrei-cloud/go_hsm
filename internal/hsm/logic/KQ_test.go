package logic

import (
	"encoding/hex"
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecuteKQ(t *testing.T) {
	t.Parallel()

	// Initialize the test LMK provider.
	if err := SetupTestLMKProvider(); err != nil {
		t.Fatalf("Failed to setup test LMK provider: %v", err)
	}

	// Test MK-AC that will be properly encrypted under test LMK.
	validMKACHex := "0123456789ABCDEFFEDCBA9876543210"

	// Test data components.
	validPANPSN, _ := hex.DecodeString(
		"1111111111111100",
	) // 8-byte PAN/PSN field.
	validATC, _ := hex.DecodeString(
		"005E",
	) // 2-byte ATC.
	validUN, _ := hex.DecodeString(
		"52BF4585",
	) // 4-byte UN.
	validTxnDataLen := "25"                                                                         // 2-byte HEX (37 decimal bytes) length.
	validTxnDataHex := "0000000123000000000000000784800004800008402505220052BF45851800005E06011203" // 74 hex chars (37 bytes).
	validTxnData, _ := hex.DecodeString(validTxnDataHex)
	validDelimiter := ";"
	validARQC, _ := hex.DecodeString("076C5766F738E9A6") // 8-byte ARQC.
	validARC, _ := hex.DecodeString("3030")              // 2-byte ARC (ASCII "00").

	tests := []struct {
		name        string
		inputFunc   func() []byte
		expectedErr error
		expectKR00  bool
		expectARPC  bool
	}{
		{
			name: "Empty input",
			inputFunc: func() []byte {
				return []byte{}
			},
			expectedErr: errorcodes.Err15,
		},
		{
			name: "Input too short",
			inputFunc: func() []byte {
				return []byte("00")
			},
			expectedErr: errorcodes.Err15,
		},
		{
			name: "Unsupported scheme 1",
			inputFunc: func() []byte {
				input := []byte("01")
				input = append(input, []byte(validMKACHex)...)
				input = append(input, validPANPSN...)
				input = append(input, validATC...)
				input = append(input, validUN...)
				input = append(input, []byte(validTxnDataLen)...)
				input = append(input, []byte(validTxnData)...)
				input = append(input, []byte(validDelimiter)...)
				input = append(input, validARQC...)

				return input
			},
			expectedErr: errorcodes.Err68,
		},
		{
			name: "Unsupported mode 3",
			inputFunc: func() []byte {
				input := []byte("30")
				input = append(input, []byte(validMKACHex)...)
				input = append(input, validPANPSN...)
				input = append(input, validATC...)
				input = append(input, validUN...)
				input = append(input, []byte(validTxnDataLen)...)
				input = append(input, []byte(validTxnData)...)
				input = append(input, []byte(validDelimiter)...)
				input = append(input, validARQC...)

				return input
			},
			expectedErr: errorcodes.Err68,
		},
		{
			name: "Invalid MK-AC hex",
			inputFunc: func() []byte {
				input := []byte("00GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG")
				input = append(input, validPANPSN...)
				input = append(input, validATC...)
				input = append(input, validUN...)
				input = append(input, []byte(validTxnDataLen)...)
				input = append(input, []byte(validTxnData)...)
				input = append(input, []byte(validDelimiter)...)
				input = append(input, validARQC...)

				return input
			},
			expectedErr: errorcodes.Err15,
		},
		{
			name: "MK-AC too short",
			inputFunc: func() []byte {
				input := []byte("001234567890ABCDEF")
				input = append(input, validPANPSN...)
				input = append(input, validATC...)
				input = append(input, validUN...)
				input = append(input, []byte(validTxnDataLen)...)
				input = append(input, []byte(validTxnData)...)
				input = append(input, []byte(validDelimiter)...)
				input = append(input, validARQC...)

				return input
			},
			expectedErr: errorcodes.Err15,
		},
		{
			name: "Missing PAN/PSN",
			inputFunc: func() []byte {
				input := []byte("00")
				input = append(input, []byte(validMKACHex)...)
				input = append(input, []byte("1234")...)

				return input
			},
			expectedErr: errorcodes.Err15,
		},
		{
			name: "Missing ATC",
			inputFunc: func() []byte {
				input := []byte("00")
				input = append(input, []byte(validMKACHex)...)
				input = append(input, validPANPSN...)
				input = append(input, []byte("12")...)

				return input
			},
			expectedErr: errorcodes.Err15,
		},
		{
			name: "Missing UN",
			inputFunc: func() []byte {
				input := []byte("00")
				input = append(input, []byte(validMKACHex)...)
				input = append(input, validPANPSN...)
				input = append(input, validATC...)
				input = append(input, []byte("12")...)

				return input
			},
			expectedErr: errorcodes.Err15,
		},
		{
			name: "Invalid transaction data length hex",
			inputFunc: func() []byte {
				input := []byte("00")
				input = append(input, []byte(validMKACHex)...)
				input = append(input, validPANPSN...)
				input = append(input, validATC...)
				input = append(input, validUN...)
				input = append(input, []byte("GG")...)

				return input
			},
			expectedErr: errorcodes.Err15,
		},
		{
			name: "Zero transaction data length",
			inputFunc: func() []byte {
				input := []byte("00")
				input = append(input, []byte(validMKACHex)...)
				input = append(input, validPANPSN...)
				input = append(input, validATC...)
				input = append(input, validUN...)
				input = append(input, []byte("00")...)
				input = append(input, []byte(validDelimiter)...)
				input = append(input, validARQC...)

				return input
			},
			expectedErr: errorcodes.Err80,
		},
		{
			name: "Transaction data length too large",
			inputFunc: func() []byte {
				input := []byte("00")
				input = append(input, []byte(validMKACHex)...)
				input = append(input, validPANPSN...)
				input = append(input, validATC...)
				input = append(input, validUN...)
				input = append(input, []byte("FF")...)
				input = append(input, make([]byte, 255)...)
				input = append(input, []byte(validDelimiter)...)
				input = append(input, validARQC...)

				return input
			},
			expectedErr: errorcodes.Err80, // Will fail before length validation due to insufficient data.
		},
		{
			name: "Missing transaction data",
			inputFunc: func() []byte {
				input := []byte("00")
				input = append(input, []byte(validMKACHex)...)
				input = append(input, validPANPSN...)
				input = append(input, validATC...)
				input = append(input, validUN...)
				input = append(input, []byte(validTxnDataLen)...)

				return input
			},
			expectedErr: errorcodes.Err15,
		},
		{
			name: "Missing delimiter",
			inputFunc: func() []byte {
				input := []byte("00")
				input = append(input, []byte(validMKACHex)...)
				input = append(input, validPANPSN...)
				input = append(input, validATC...)
				input = append(input, validUN...)
				input = append(input, []byte(validTxnDataLen)...)
				input = append(input, []byte(validTxnData)...)
				input = append(input, validARQC...)

				return input
			},
			expectedErr: errorcodes.Err15,
		},
		{
			name: "Missing ARQC",
			inputFunc: func() []byte {
				input := []byte("00")
				input = append(input, []byte(validMKACHex)...)
				input = append(input, validPANPSN...)
				input = append(input, validATC...)
				input = append(input, validUN...)
				input = append(input, []byte(validTxnDataLen)...)
				input = append(input, []byte(validTxnData)...)
				input = append(input, []byte(validDelimiter)...)

				return input
			},
			expectedErr: errorcodes.Err15,
		},
		{
			name: "Mode 1 missing ARC",
			inputFunc: func() []byte {
				input := []byte("10")
				input = append(input, []byte(validMKACHex)...)
				input = append(input, validPANPSN...)
				input = append(input, validATC...)
				input = append(input, validUN...)
				input = append(input, []byte(validTxnDataLen)...)
				input = append(input, []byte(validTxnData)...)
				input = append(input, []byte(validDelimiter)...)
				input = append(input, validARQC...)

				return input
			},
			expectedErr: errorcodes.Err15,
		},

		{
			name: "Valid Mode 0 - ARQC verification only",
			inputFunc: func() []byte {
				input := []byte("00")
				input = append(input, []byte(validMKACHex)...)
				input = append(input, validPANPSN...)
				input = append(input, validATC...)
				input = append(input, validUN...)
				input = append(input, []byte(validTxnDataLen)...)
				// decode transaction data hex to raw bytes.
				txnRaw, err := hex.DecodeString(validTxnDataHex)
				require.NoError(t, err)
				input = append(input, txnRaw...)
				input = append(input, []byte(validDelimiter)...)
				input = append(input, validARQC...)

				return input
			},
			expectKR00: true,
		},
		{
			name: "Valid Mode 1 - ARQC verification and ARPC generation",
			inputFunc: func() []byte {
				input := []byte("10")
				input = append(input, []byte(validMKACHex)...)
				input = append(input, validPANPSN...)
				input = append(input, validATC...)
				input = append(input, validUN...)
				input = append(input, []byte(validTxnDataLen)...)
				// decode transaction data hex to raw bytes.
				txnRaw1, err := hex.DecodeString(validTxnDataHex)
				require.NoError(t, err)
				input = append(input, txnRaw1...)
				input = append(input, []byte(validDelimiter)...)
				input = append(input, validARQC...)
				input = append(input, validARC...)

				return input
			},
			expectKR00: true,
			expectARPC: true,
		},
		{
			name: "Valid Mode 2 - ARPC generation only",
			inputFunc: func() []byte {
				input := []byte("20")
				input = append(input, []byte(validMKACHex)...)
				input = append(input, validPANPSN...)
				input = append(input, validATC...)
				input = append(input, validUN...)
				input = append(input, []byte(validTxnDataLen)...)
				// decode transaction data hex to raw bytes.
				txnRaw2, err := hex.DecodeString(validTxnDataHex)
				require.NoError(t, err)
				input = append(input, txnRaw2...)
				input = append(input, []byte(validDelimiter)...)
				input = append(input, validARQC...)
				input = append(input, validARC...)

				return input
			},
			expectKR00: true,
			expectARPC: true,
		},
	}

	for _, tt := range tests {
		tt := tt // Capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := ExecuteKQ(tt.inputFunc())

			if tt.expectedErr != nil {
				assert.Error(t, err)
				assert.Equal(t, tt.expectedErr, err)
				assert.Nil(t, result)

				return
			}

			require.NoError(t, err)
			if tt.expectKR00 {
				assert.Equal(t, "KR00", string(result[:4]))

				if tt.expectARPC {
					// Should have ARPC appended (16 hex characters).
					assert.Equal(
						t,
						20,
						len(result),
						"Expected KR00 + 16 hex chars for ARPC",
					)
					// Verify ARPC is valid hex.
					arpcHex := string(result[4:])
					_, err := hex.DecodeString(arpcHex)
					assert.NoError(t, err, "ARPC should be valid hex")
				} else {
					// Mode 0 should only return KR00.
					assert.Equal(t, 4, len(result), "Mode 0 should only return KR00")
				}
			}
		})
	}
}
