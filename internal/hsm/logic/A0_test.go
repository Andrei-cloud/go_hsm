package logic

import (
	"encoding/hex"
	"testing"
)

// mockLMK provides a no-op implementation for tests.
func mockLMK(data []byte) ([]byte, error) {
	return data, nil
}

// TestExecuteA0ShortInput verifies that ExecuteA0 returns an error for inputs shorter than 5 bytes.
func TestExecuteA0ShortInput(t *testing.T) {
	t.Parallel()
	_, err := ExecuteA0([]byte{1, 2, 3, 4}, mockLMK, mockLMK)
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

// TestExecuteA0NoZMK verifies ExecuteA0 returns a valid response without a ZMK field.
func TestExecuteA0NoZMK(t *testing.T) {
	t.Parallel()
	// mode='0', keyType(3 bytes) and keyScheme.
	input := []byte{'0', 'K', 'T', 'Y', 'X'}
	resp, err := ExecuteA0(input, mockLMK, mockLMK)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// "4 (A100) + 1('U') + 32(hex) + 6(KCV) = 43".
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

// TestExecuteA0WithZMK verifies ExecuteA0 handles a ZMK field and still appends a single KCV.
func TestExecuteA0WithZMK(t *testing.T) {
	t.Parallel()
	// dummy ZMK: 'U' + 32 'A'
	hexZmk := make([]byte, 32)
	for i := range hexZmk {
		hexZmk[i] = 'A'
	}
	zmkField := append([]byte{'U'}, hexZmk...)
	input := append([]byte{'1', 'K', 'T', 'Y', 'Z'}, zmkField...)
	resp, err := ExecuteA0(input, mockLMK, mockLMK)
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
