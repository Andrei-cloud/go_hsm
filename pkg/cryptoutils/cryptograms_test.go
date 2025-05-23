package cryptoutils

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestGenerateARQC10 uses table-driven tests to verify GenerateARQC10 output.
func TestGenerateARQC10(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		issMKACsting string
		data         string
		arqc         []byte
		pan          string
		psn          string
		wantARQC     []byte
		wantErr      bool
	}{
		{
			name:         "visa cvn10 method1",
			issMKACsting: "0123456789ABCDEFFEDCBA9876543210",
			data:         "0000000123000000000000000784800004800008402505220052BF45851800005E06011203",
			pan:          "4111111111111111",
			psn:          "00",
			wantARQC:     []byte("076C5766F738E9A6"),
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rawData, err := hex.DecodeString(tt.data)
			if err != nil {
				t.Fatalf("rawData hex.DecodeString() error = %v", err)
			}

			rawARQC, err := hex.DecodeString(string(tt.wantARQC))
			if err != nil {
				t.Fatalf("rawARQC hex.DecodeString() error = %v", err)
			}

			issMKAC, err := hex.DecodeString(tt.issMKACsting)
			if err != nil {
				t.Fatalf("issMKAC hex.DecodeString() error = %v", err)
			}

			got, err := GenerateARQC10(issMKAC, rawData, tt.pan, tt.psn)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GenerateARQC10() error = %v; wantErr %v", err, tt.wantErr)
			}

			if !bytes.Equal(got[:len(tt.wantARQC)/2], rawARQC) {
				t.Errorf("GenerateARQC10() = %x; want %s", got[:len(tt.wantARQC)/2], tt.wantARQC)
			}
		})
	}
}

func TestGenerateARQC18(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		issMKACsting string
		data         string
		atc          string
		arqc         []byte
		pan          string
		psn          string
		wantARQC     []byte
		wantErr      bool
	}{
		{
			name:         "visa cvn18 method2",
			issMKACsting: "0123456789ABCDEFFEDCBA9876543210",
			data:         "0000000123000000000000000784800004800008402505220052BF45851800005E06011203A0B800",
			pan:          "4111111111111111",
			psn:          "00",
			atc:          "005E",
			wantARQC:     []byte("FDBA87A3C606B92F"),
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rawData, err := hex.DecodeString(tt.data)
			if err != nil {
				t.Fatalf("rawData hex.DecodeString() error = %v", err)
			}

			rawARQC, err := hex.DecodeString(string(tt.wantARQC))
			if err != nil {
				t.Fatalf("rawARQC hex.DecodeString() error = %v", err)
			}

			issMKAC, err := hex.DecodeString(tt.issMKACsting)
			if err != nil {
				t.Fatalf("issMKAC hex.DecodeString() error = %v", err)
			}

			atc, err := hex.DecodeString(tt.atc)
			if err != nil {
				t.Fatalf("atc hex.DecodeString() error = %v", err)
			}

			got, err := GenerateARQC18(issMKAC, rawData, atc, tt.pan, tt.psn)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GenerateARQC18() error = %v; wantErr %v", err, tt.wantErr)
			}

			if !bytes.Equal(got[:len(tt.wantARQC)/2], rawARQC) {
				t.Errorf("GenerateARQC18() = %x; want %s", got[:len(tt.wantARQC)/2], tt.wantARQC)
			}
		})
	}
}
