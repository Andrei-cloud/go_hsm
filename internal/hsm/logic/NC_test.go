// nolint:all // test package
package logic

import (
	"bytes"
	"testing"
)

// TestExecuteNCShortInput verifies that ExecuteNC returns an error for inputs shorter than 48 bytes.
func TestExecuteNCShortInput(t *testing.T) {
	t.Parallel()
	_, err := ExecuteNC([]byte{1}, mockLMK, mockLMK)
	if err == nil {
		t.Fatal("expected error for short input")
	}
}

// TestExecuteNCSuccess verifies that ExecuteNC returns a response starting with "ND00" and preserving firmware suffix.
func TestExecuteNCSuccess(t *testing.T) {
	t.Parallel()
	// call with dummy input; firmware constant is appended by logic
	dummy := []byte{0, 0}

	out, err := ExecuteNC(dummy, mockLMK, mockLMK)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) < 4 {
		t.Fatalf("output too short: %d", len(out))
	}
	if string(out[:4]) != "ND00" {
		t.Errorf("expected prefix ND00, got %s", out[:4])
	}
	// expect firmware version constant appended
	const fw = "0007-E000"
	if !bytes.HasSuffix(out, []byte(fw)) {
		t.Errorf("expected firmware suffix %q, got %x", fw, out)
	}
}
