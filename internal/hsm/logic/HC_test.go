package logic

import (
	"encoding/hex"
	"testing"
)

func TestExecuteHC_Basic(t *testing.T) {
	// Example: U-prefixed double-length key, dummy values.
	clearKey := make([]byte, 16)
	for i := range clearKey {
		clearKey[i] = byte(i + 1)
	}
	encKeyHex := hex.EncodeToString(clearKey)
	input := append([]byte{'U'}, []byte(encKeyHex)...)
	input = append(input, []byte("HC")...)

	resp, err := ExecuteHC(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp) < 4+1+32+1+32 { // HD00 + U + 32 + U + 32
		t.Errorf("response too short: %d", len(resp))
	}
}
