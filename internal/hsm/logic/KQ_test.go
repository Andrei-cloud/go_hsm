package logic

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/stretchr/testify/assert"
)

func TestExecuteKQ(t *testing.T) {
	t.Parallel()

	// Set timeout for the entire test.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Initialize the test LMK provider.
	if err := SetupTestLMKProvider(); err != nil {
		t.Fatalf("Failed to setup test LMK provider: %v", err)
	}

	// Test MK-AC that will be properly encrypted under test LMK.
	testMKAC := "0123456789ABCDEFFEDCBA9876543210"
	mkacBytes, _ := hex.DecodeString(testMKAC)
	encryptedMKAC, err := LMKProviderInstance.EncryptUnderLMK(mkacBytes, "000", 'U')
	if err != nil {
		t.Fatalf("Failed to encrypt test MK-AC: %v", err)
	}
	validMKACHex := hex.EncodeToString(encryptedMKAC)

	// Test data components.
	validPANPSN := "411111111111111100" // 8-byte PAN/PSN field.
	validATC := "005E"                  // 2-byte ATC.
	validUN := "06011203"               // 4-byte UN.
	validTxnDataLen := "10"             // 1-byte length (16 bytes).
	validTxnData := "0000000123000000"  // 8-byte transaction data.
	validDelimiter := ";"
	validARQC := "076C5766F738E9A6" // 8-byte ARQC.
	validARC := "3030"              // 2-byte ARC.

	tests := []struct {
		name        string
		input       string
		expectedErr error
		expectKR00  bool
		expectARPC  bool
	}{
		{
			name:        "Empty input",
			input:       "",
			expectedErr: errorcodes.Err15,
		},
		{
			name:        "Input too short",
			input:       "00",
			expectedErr: errorcodes.Err15,
		},
		{
			name:        "Unsupported scheme 1",
			input:       "01" + validMKACHex + validPANPSN + validATC + validUN + validTxnDataLen + validTxnData + validDelimiter + validARQC,
			expectedErr: errorcodes.Err68,
		},
		{
			name:        "Unsupported mode 3",
			input:       "30" + validMKACHex + validPANPSN + validATC + validUN + validTxnDataLen + validTxnData + validDelimiter + validARQC,
			expectedErr: errorcodes.Err68,
		},
		{
			name:        "Invalid MK-AC hex",
			input:       "00GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG" + validPANPSN + validATC + validUN + validTxnDataLen + validTxnData + validDelimiter + validARQC,
			expectedErr: errorcodes.Err15,
		},
		{
			name:        "MK-AC too short",
			input:       "001234567890ABCDEF" + validPANPSN + validATC + validUN + validTxnDataLen + validTxnData + validDelimiter + validARQC,
			expectedErr: errorcodes.Err15,
		},
		{
			name:        "Missing PAN/PSN",
			input:       "00" + validMKACHex + "1234",
			expectedErr: errorcodes.Err15,
		},
		{
			name:        "Missing ATC",
			input:       "00" + validMKACHex + validPANPSN + "12",
			expectedErr: errorcodes.Err15,
		},
		{
			name:        "Missing UN",
			input:       "00" + validMKACHex + validPANPSN + validATC + "12",
			expectedErr: errorcodes.Err15,
		},
		{
			name:        "Invalid transaction data length hex",
			input:       "00" + validMKACHex + validPANPSN + validATC + validUN + "GG",
			expectedErr: errorcodes.Err15,
		},
		{
			name:        "Zero transaction data length",
			input:       "00" + validMKACHex + validPANPSN + validATC + validUN + "00" + validDelimiter + validARQC,
			expectedErr: errorcodes.Err80,
		},
		{
			name: "Transaction data length too large",
			input: "00" + validMKACHex + validPANPSN + validATC + validUN + "FF" + string(
				make([]byte, 255),
			) + validDelimiter + validARQC,
			expectedErr: errorcodes.Err15, // Will fail before length validation due to insufficient data.
		},
		{
			name:        "Missing transaction data",
			input:       "00" + validMKACHex + validPANPSN + validATC + validUN + validTxnDataLen,
			expectedErr: errorcodes.Err15,
		},
		{
			name:        "Missing delimiter",
			input:       "00" + validMKACHex + validPANPSN + validATC + validUN + validTxnDataLen + validTxnData + validARQC,
			expectedErr: errorcodes.Err15,
		},
		{
			name:        "Missing ARQC",
			input:       "00" + validMKACHex + validPANPSN + validATC + validUN + validTxnDataLen + validTxnData + validDelimiter,
			expectedErr: errorcodes.Err15,
		},
		{
			name:        "Mode 1 missing ARC",
			input:       "10" + validMKACHex + validPANPSN + validATC + validUN + validTxnDataLen + validTxnData + validDelimiter + validARQC,
			expectedErr: errorcodes.Err15,
		},
		{
			name:        "Mode 2 missing ARC",
			input:       "20" + validMKACHex + validPANPSN + validATC + validUN + validTxnDataLen + validTxnData + validDelimiter + validARQC,
			expectedErr: errorcodes.Err15,
		},
		{
			name:       "Valid Mode 0 - ARQC verification only",
			input:      "00" + validMKACHex + validPANPSN + validATC + validUN + validTxnDataLen + validTxnData + validDelimiter + validARQC,
			expectKR00: true,
		},
		{
			name:       "Valid Mode 1 - ARQC verification and ARPC generation",
			input:      "10" + validMKACHex + validPANPSN + validATC + validUN + validTxnDataLen + validTxnData + validDelimiter + validARQC + validARC,
			expectKR00: true,
			expectARPC: true,
		},
		{
			name:       "Valid Mode 2 - ARPC generation only",
			input:      "20" + validMKACHex + validPANPSN + validATC + validUN + validTxnDataLen + validTxnData + validDelimiter + validARQC + validARC,
			expectKR00: true,
			expectARPC: true,
		},
	}

	for _, tt := range tests {
		tt := tt // Capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// Set timeout for individual test case.
			testCtx, testCancel := context.WithTimeout(ctx, 10*time.Second)
			defer testCancel()

			// Channel to receive result.
			resultChan := make(chan struct {
				result []byte
				err    error
			}, 1)

			go func() {
				result, err := ExecuteKQ([]byte(tt.input))
				resultChan <- struct {
					result []byte
					err    error
				}{result, err}
			}()

			select {
			case res := <-resultChan:
				if tt.expectedErr != nil {
					assert.Error(t, res.err)
					assert.Equal(t, tt.expectedErr, res.err)
					assert.Nil(t, res.result)
					return
				}

				assert.NoError(t, res.err)

				if tt.expectKR00 {
					assert.True(t, len(res.result) >= 4)
					assert.Equal(t, "KR00", string(res.result[:4]))

					if tt.expectARPC {
						// Should have ARPC appended (16 hex characters).
						assert.Equal(
							t,
							20,
							len(res.result),
							"Expected KR00 + 16 hex chars for ARPC",
						)
						// Verify ARPC is valid hex.
						arpcHex := string(res.result[4:])
						_, err := hex.DecodeString(arpcHex)
						assert.NoError(t, err, "ARPC should be valid hex")
					} else {
						// Mode 0 should only return KR00.
						assert.Equal(t, 4, len(res.result), "Mode 0 should only return KR00")
					}
				}
			case <-testCtx.Done():
				t.Fatalf("Test %s timed out", tt.name)
			}
		})
	}
}

func TestExecuteKQARQCFailure(t *testing.T) {
	t.Parallel()

	// Set timeout for the test.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Initialize the test LMK provider.
	if err := SetupTestLMKProvider(); err != nil {
		t.Fatalf("Failed to setup test LMK provider: %v", err)
	}

	// Use test MK-AC.
	testMKAC := "0123456789ABCDEFFEDCBA9876543210"
	mkacBytes, _ := hex.DecodeString(testMKAC)
	encryptedMKAC, err := LMKProviderInstance.EncryptUnderLMK(mkacBytes, "000", 'U')
	if err != nil {
		t.Fatalf("Failed to encrypt test MK-AC: %v", err)
	}
	validMKACHex := hex.EncodeToString(encryptedMKAC)

	// Use wrong ARQC to trigger verification failure.
	wrongARQC := "FFFFFFFFFFFFFFFF"

	input := "00" + validMKACHex + "411111111111111100" + "005E" + "06011203" + "08" + "0000000123000000" + ";" + wrongARQC

	// Channel to receive result.
	resultChan := make(chan struct {
		result []byte
		err    error
	}, 1)

	go func() {
		result, err := ExecuteKQ([]byte(input))
		resultChan <- struct {
			result []byte
			err    error
		}{result, err}
	}()

	select {
	case res := <-resultChan:
		assert.Error(t, res.err)
		assert.Equal(t, errorcodes.Err01, res.err)
		assert.Nil(t, res.result)
	case <-ctx.Done():
		t.Fatal("Test timed out")
	}
}

func TestExecuteKQInvalidTransactionDataLength(t *testing.T) {
	t.Parallel()

	// Set timeout for the test.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// Initialize the test LMK provider.
	if err := SetupTestLMKProvider(); err != nil {
		t.Fatalf("Failed to setup test LMK provider: %v", err)
	}

	// Use test MK-AC.
	testMKAC := "0123456789ABCDEFFEDCBA9876543210"
	mkacBytes, _ := hex.DecodeString(testMKAC)
	encryptedMKAC, err := LMKProviderInstance.EncryptUnderLMK(mkacBytes, "000", 'U')
	if err != nil {
		t.Fatalf("Failed to encrypt test MK-AC: %v", err)
	}
	validMKACHex := hex.EncodeToString(encryptedMKAC)

	tests := []struct {
		name          string
		dataLengthHex string
		expectedErr   error
	}{
		{
			name:          "Transaction data length 0",
			dataLengthHex: "00",
			expectedErr:   errorcodes.Err80,
		},
		{
			name:          "Transaction data length 256 (overflow)",
			dataLengthHex: "FF",             // This will be valid as 255, but we'll test the upper bound.
			expectedErr:   errorcodes.Err15, // Will fail due to insufficient data length.
		},
	}

	for _, tt := range tests {
		tt := tt // Capture range variable.
		t.Run(tt.name, func(t *testing.T) {
			// Set timeout for individual test case.
			testCtx, testCancel := context.WithTimeout(ctx, 5*time.Second)
			defer testCancel()

			// Create input with specific transaction data length.
			input := "00" + validMKACHex + "411111111111111100" + "005E" + "06011203" + tt.dataLengthHex

			// For FF length, we need to add 255 bytes + delimiter + ARQC to avoid early length failure.
			if tt.dataLengthHex == "FF" {
				input += string(make([]byte, 255)) + ";" + "076C5766F738E9A6"
			} else {
				// For 00 length, add delimiter and ARQC.
				input += ";" + "076C5766F738E9A6"
			}

			// Channel to receive result.
			resultChan := make(chan struct {
				result []byte
				err    error
			}, 1)

			go func() {
				result, err := ExecuteKQ([]byte(input))
				resultChan <- struct {
					result []byte
					err    error
				}{result, err}
			}()

			select {
			case res := <-resultChan:
				assert.Error(t, res.err)
				assert.Equal(t, tt.expectedErr, res.err)
				assert.Nil(t, res.result)
			case <-testCtx.Done():
				t.Fatalf("Test %s timed out", tt.name)
			}
		})
	}
}
