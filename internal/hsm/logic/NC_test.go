package logic

import (
	"bytes"
	"testing"
)

// TestExecuteNCShortInput verifies that ExecuteNC returns an error for inputs shorter than 48 bytes.
func TestExecuteNCShortInput(t *testing.T) {
	t.Parallel()
	_, err := ExecuteNC([]byte{1})
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

// TestExecuteNCSuccess verifies that ExecuteNC returns a response starting with "ND00" and preserving firmware suffix.
func TestExecuteNCSuccess(t *testing.T) {
	t.Parallel()
	keyHex := []byte("1234567890ABCDEFFEDCBA0987654321001234567890ABCDEF")
	firmware := []byte("FW")
	input := append(keyHex, firmware...)

	out, err := ExecuteNC(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) < 4 {
		t.Fatalf("output too short: %d", len(out))
	}
	if string(out[:4]) != "ND00" {
		t.Errorf("expected prefix ND00, got %s", out[:4])
	}
	if !bytes.HasSuffix(out, firmware) {
		t.Errorf("expected firmware suffix, got %x", out)
	}
}
