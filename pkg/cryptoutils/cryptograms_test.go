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

func TestGenerateARPC10(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		issMKACsting string
		data         string
		atc          string
		arqc         string
		pan          string
		psn          string
		rc           string
		wantARPC     string
		wantErr      bool
	}{
		{
			name:         "cvn18 method2",
			issMKACsting: "0123456789ABCDEFFEDCBA9876543210",
			data:         "0000000123000000000000000784800004800008402505220052BF45851800005E06011203A0B800",
			pan:          "4111111111111111",
			psn:          "00",
			atc:          "005E",
			rc:           "3030",
			arqc:         "076C5766F738E9A6",
			wantARPC:     "85BC09B3A4809DE6",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			arqc, err := hex.DecodeString(tt.arqc)
			if err != nil {
				t.Fatalf("rawData hex.DecodeString() error = %v", err)
			}

			issMKAC, err := hex.DecodeString(tt.issMKACsting)
			if err != nil {
				t.Fatalf("issMKAC hex.DecodeString() error = %v", err)
			}

			rawARPC, err := hex.DecodeString(tt.wantARPC)
			if err != nil {
				t.Fatalf("rawARPC hex.DecodeString() error = %v", err)
			}

			rc, err := hex.DecodeString(tt.rc)
			if err != nil {
				t.Fatalf("rc hex.DecodeString() error = %v", err)
			}

			got, err := GenerateARPC10(issMKAC, arqc, rc, tt.pan, tt.psn)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GenerateARPC10() error = %v; wantErr %v", err, tt.wantErr)
			}

			if !bytes.Equal(got[:len(tt.wantARPC)/2], rawARPC) {
				t.Errorf("GenerateARQC18() = %x; want %s", got[:len(tt.wantARPC)/2], tt.wantARPC)
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
			name:         "cvn18 method2",
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

func TestGenerateARPC18(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		issMKACsting string
		data         string
		atc          string
		arqc         string
		pan          string
		psn          string
		csu          string
		wantARPC     string
		wantErr      bool
	}{
		{
			name:         "cvn18 method2",
			issMKACsting: "0123456789ABCDEFFEDCBA9876543210",
			data:         "0000000123000000000000000784800004800008402505220052BF45851800005E06011203A0B800",
			pan:          "4111111111111111",
			psn:          "00",
			atc:          "005E",
			csu:          "00000000",
			arqc:         "FDBA87A3C606B92F",
			wantARPC:     "FA12E21A",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			arqc, err := hex.DecodeString(tt.arqc)
			if err != nil {
				t.Fatalf("rawData hex.DecodeString() error = %v", err)
			}

			issMKAC, err := hex.DecodeString(tt.issMKACsting)
			if err != nil {
				t.Fatalf("issMKAC hex.DecodeString() error = %v", err)
			}

			atc, err := hex.DecodeString(tt.atc)
			if err != nil {
				t.Fatalf("atc hex.DecodeString() error = %v", err)
			}

			csu, err := hex.DecodeString(tt.csu)
			if err != nil {
				t.Fatalf("csu hex.DecodeString() error = %v", err)
			}

			rawARPC, err := hex.DecodeString(tt.wantARPC)
			if err != nil {
				t.Fatalf("rawARPC hex.DecodeString() error = %v", err)
			}

			got, err := GenerateARPC18(issMKAC, tt.pan, tt.psn, atc, arqc, csu, nil)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GenerateARQC18() error = %v; wantErr %v", err, tt.wantErr)
			}

			if !bytes.Equal(got[:len(tt.wantARPC)/2], rawARPC) {
				t.Errorf("GenerateARQC18() = %x; want %s", got[:len(tt.wantARPC)/2], tt.wantARPC)
			}
		})
	}
}

func TestGenerateARQC22(t *testing.T) {
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
			name:         "cvn22 method2",
			issMKACsting: "0123456789ABCDEFFEDCBA9876543210",
			data:         "0000000123000000000000000784800004800008402505220052BF45851800005E06011203A0B800",
			pan:          "4111111111111111",
			psn:          "00",
			atc:          "005E",
			wantARQC:     []byte("FDBA87A3C606B92F"),
			wantErr:      false,
		},
		{
			name:         "cvn22 method2 test 2",
			issMKACsting: "0123456789ABCDEFFEDCBA9876543210",
			data:         "0000000040000000000000000124800004800001241911050152BF45851800001C06011203A0B800",
			pan:          "1234567890123456",
			psn:          "00",
			atc:          "001C",
			wantARQC:     []byte("7A788EA6B8A3E733"),
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

			got, err := GenerateARQC22(issMKAC, rawData, atc, tt.pan, tt.psn)
			if (err != nil) != tt.wantErr {
				t.Fatalf("GenerateARQC22() error = %v; wantErr %v", err, tt.wantErr)
			}

			if !bytes.Equal(got[:len(tt.wantARQC)/2], rawARQC) {
				t.Errorf("GenerateARQC22() = %x; want %s", got[:len(tt.wantARQC)/2], tt.wantARQC)
			}
		})
	}
}
