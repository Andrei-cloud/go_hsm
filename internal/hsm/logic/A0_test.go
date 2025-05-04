package logic

import (
	"encoding/hex"
	"testing"
)

// mockLMK provides a triple-length key for tests
func mockLMK(data []byte) ([]byte, error) {
	// Return triple-length key for proper DES operations
	result := make([]byte, 24)
	for i := range result {
		result[i] = byte(i + 1) // Predictable non-zero bytes
	}
	return result, nil
}

func mockLog(_ string) {}

func TestExecuteA0ShortInput(t *testing.T) {
	t.Parallel()
	_, err := ExecuteA0([]byte{1, 2, 3, 4}, mockLMK, mockLMK, mockLog)
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

func TestExecuteA0NoZMK(t *testing.T) {
	t.Parallel()
	// mode='0', keyType='000', keyScheme='U' (double-length key)
	input := []byte{'0', '0', '0', '0', 'U'}
	resp, err := ExecuteA0(input, mockLMK, mockLMK, mockLog)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 4 (A100) + 1('U') + 32(hex) + 6(KCV) = 43
	if len(resp) != 43 {
		t.Errorf("expected length 43, got %d", len(resp))
	}
	if string(resp[:4]) != "A100" {
		t.Errorf("expected prefix A100, got %q", resp[:4])
	}
	if resp[4] != 'U' {
		t.Errorf("expected 'U' at position 4, got %q", resp[4])
	}
	// verify the last 6 bytes are valid hex for the KCV
	if _, err := hex.DecodeString(string(resp[len(resp)-6:])); err != nil {
		t.Errorf("expected valid 6-hex-digit KCV, got %q", resp[len(resp)-6:])
	}
}

func TestExecuteA0WithZMK(t *testing.T) {
	t.Parallel()
	// Create triple-length hex ZMK (24 bytes -> 48 hex chars)
	hexZmk := make([]byte, 48)
	for i := range hexZmk {
		hexZmk[i] = 'F'
	}

	// Construct input: mode='1', keyType='000', keyScheme='U'
	// Followed by ZMK field: scheme='T' (triple-length) + 48 hex chars
	input := append([]byte{'1', '0', '0', '0', 'U', 'T'}, hexZmk...)

	resp, err := ExecuteA0(input, mockLMK, mockLMK, mockLog)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// 4 + 1 + 32 (under LMK) + 1 + 32 (under ZMK) + 6 (KCV) = 76
	if len(resp) != 76 {
		t.Errorf("expected length 76, got %d", len(resp))
	}
	if string(resp[:4]) != "A100" {
		t.Errorf("expected prefix A100, got %q", resp[:4])
	}
	// verify the second 'U' at offset 37 (4+1+32)
	if resp[37] != 'U' {
		t.Errorf("expected 'U' at position 37, got %q", resp[37])
	}
	// verify final 6-hex KCV
	if _, err := hex.DecodeString(string(resp[len(resp)-6:])); err != nil {
		t.Errorf("expected valid KCV at end, got %q", resp[len(resp)-6:])
	}
}
