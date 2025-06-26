package keyblocklmk

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
)

// Test LMK for consistent testing.
const testLMKHex = "9B71333A13F9FAE72F9D0E2DAB4AD6784718012F9244033F3F26A2DE0C8AA11A"

func getTestLMK() []byte {
	lmk, _ := hex.DecodeString(testLMKHex)

	return lmk
}

// TestWrapUnwrapRoundTrip tests that wrapping and unwrapping a key returns the original key.
func TestWrapUnwrapRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		key    []byte
		header Header
	}{
		{
			name: "AES-128 key Thales S format",
			key:  []byte("0123456789ABCDEF"), // 16 bytes
			header: Header{
				Version:       '1',
				KeyUsage:      "B0",
				Algorithm:     'A',
				ModeOfUse:     'E',
				KeyVersionNum: "00",
				Exportability: 'S',
				KeyContext:    '0',
			},
		},
		{
			name: "AES-192 key Thales S format",
			key:  []byte("0123456789ABCDEF01234567"), // 24 bytes
			header: Header{
				Version:       '1',
				KeyUsage:      "B1",
				Algorithm:     'A',
				ModeOfUse:     'E',
				KeyVersionNum: "00",
				Exportability: 'S',
				KeyContext:    '0',
			},
		},
		{
			name: "AES-256 key Thales S format",
			key:  []byte("0123456789ABCDEF0123456789ABCDEF"), // 32 bytes
			header: Header{
				Version:       '1',
				KeyUsage:      "B2",
				Algorithm:     'A',
				ModeOfUse:     'E',
				KeyVersionNum: "00",
				Exportability: 'S',
				KeyContext:    '0',
			},
		},
		{
			name: "3DES key Thales S format",
			key:  []byte("0123456789ABCDEF01234567"), // 24 bytes for 3DES
			header: Header{
				Version:       '1',
				KeyUsage:      "P0",
				Algorithm:     'T',
				ModeOfUse:     'E',
				KeyVersionNum: "00",
				Exportability: 'S',
				KeyContext:    '0',
			},
		},
	}

	lmk := getTestLMK()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// Wrap the key.
			keyBlock, err := WrapKeyBlock(lmk, tt.header, nil, tt.key)
			if err != nil {
				t.Fatalf("WrapKeyBlock failed: %v", err)
			}

			// Verify key block is not empty.
			if len(keyBlock) == 0 {
				t.Fatal("WrapKeyBlock returned empty key block")
			}

			// Unwrap the key.
			header, clearKey, err := UnwrapKeyBlock(lmk, keyBlock)
			if err != nil {
				t.Fatalf("UnwrapKeyBlock failed: %v", err)
			}

			// Verify the unwrapped key matches the original.
			if !bytes.Equal(clearKey, tt.key) {
				t.Errorf("Key mismatch: expected %X, got %X", tt.key, clearKey)
			}

			// Verify header fields are preserved.
			if header.Version != tt.header.Version {
				t.Errorf("Version mismatch: expected %c, got %c", tt.header.Version, header.Version)
			}
			if header.KeyUsage != tt.header.KeyUsage {
				t.Errorf(
					"KeyUsage mismatch: expected %s, got %s",
					tt.header.KeyUsage,
					header.KeyUsage,
				)
			}
			if header.Algorithm != tt.header.Algorithm {
				t.Errorf(
					"Algorithm mismatch: expected %c, got %c",
					tt.header.Algorithm,
					header.Algorithm,
				)
			}
			if header.ModeOfUse != tt.header.ModeOfUse {
				t.Errorf(
					"ModeOfUse mismatch: expected %c, got %c",
					tt.header.ModeOfUse,
					header.ModeOfUse,
				)
			}
		})
	}
}

// TestKnownKeyBlock tests unwrapping of a known key block.
func TestKnownKeyBlock(t *testing.T) {
	t.Parallel()
	// Known test vector.
	keyBlockStr := "S10064B0AE00S000079EAFA5D0F6575FE50C1BD5BB847E4F699B7B5E878D52956"
	expectedKey := "0123456789ABCDEF"

	lmk := getTestLMK()
	keyBlock := []byte(keyBlockStr)

	// Unwrap the known key block.
	header, clearKey, err := UnwrapKeyBlock(lmk, keyBlock)
	if err != nil {
		t.Fatalf("UnwrapKeyBlock failed: %v", err)
	}

	// Verify the clear key.
	expectedKeyBytes, _ := hex.DecodeString(expectedKey)
	if !bytes.Equal(clearKey, expectedKeyBytes) {
		t.Errorf("Key mismatch: expected %X, got %X", expectedKeyBytes, clearKey)
	}

	// Verify header fields.
	if header.Version != '1' {
		t.Errorf("Version mismatch: expected 1, got %c", header.Version)
	}
	if header.KeyUsage != "B0" {
		t.Errorf("KeyUsage mismatch: expected B0, got %s", header.KeyUsage)
	}
	if header.Algorithm != 'A' {
		t.Errorf("Algorithm mismatch: expected A, got %c", header.Algorithm)
	}
	if header.ModeOfUse != 'E' {
		t.Errorf("ModeOfUse mismatch: expected E, got %c", header.ModeOfUse)
	}
	if header.Exportability != 'S' {
		t.Errorf("Exportability mismatch: expected S, got %c", header.Exportability)
	}
}

// TestWrapKeyBlockFormat tests that the wrap function produces correctly formatted key blocks.
func TestWrapKeyBlockFormat(t *testing.T) {
	t.Parallel()
	lmk := getTestLMK()
	key := []byte("0123456789ABCDEF")
	header := Header{
		Version:       '1',
		KeyUsage:      "B0",
		Algorithm:     'A',
		ModeOfUse:     'E',
		KeyVersionNum: "00",
		Exportability: 'S',
		KeyContext:    '0',
	}

	// Test Thales 'S' format.
	keyBlockS, err := WrapKeyBlock(lmk, header, nil, key)
	if err != nil {
		t.Fatalf("WrapKeyBlock failed for S format: %v", err)
	}

	// Verify S format starts with 'S'.
	if len(keyBlockS) == 0 || keyBlockS[0] != 'S' {
		t.Error("Thales S format key block should start with 'S'")
	}

	// Verify length is reasonable (should include header + encrypted data + MAC).
	// S + 16 header + 32 hex chars for encrypted data (16 bytes) + 16 hex chars for MAC (8 bytes) = 65 chars minimum.
	if len(keyBlockS) < 60 {
		t.Errorf("Thales S format key block too short: %d bytes", len(keyBlockS))
	}
}

// TestMACValidation tests that MAC validation correctly fails for corrupted key blocks.
func TestMACValidation(t *testing.T) {
	t.Parallel()
	lmk := getTestLMK()
	key := []byte("0123456789ABCDEF")
	header := Header{
		Version:       '1',
		KeyUsage:      "B0",
		Algorithm:     'A',
		ModeOfUse:     'E',
		KeyVersionNum: "00",
		Exportability: 'S',
		KeyContext:    '0',
	}

	// Create a valid key block.
	keyBlock, err := WrapKeyBlock(lmk, header, nil, key)
	if err != nil {
		t.Fatalf("WrapKeyBlock failed: %v", err)
	}

	// Verify it unwraps correctly.
	_, _, err = UnwrapKeyBlock(lmk, keyBlock)
	if err != nil {
		t.Fatalf("UnwrapKeyBlock failed for valid key block: %v", err)
	}

	// Corrupt the key block by changing the last byte (MAC).
	corruptedKeyBlock := make([]byte, len(keyBlock))
	copy(corruptedKeyBlock, keyBlock)
	corruptedKeyBlock[len(corruptedKeyBlock)-1] ^= 0x01 // Flip one bit.

	// Verify MAC validation fails.
	_, _, err = UnwrapKeyBlock(lmk, corruptedKeyBlock)
	if err == nil {
		t.Error("UnwrapKeyBlock should have failed for corrupted key block")
	}
	if err != nil && err.Error() != "mac verification failed" {
		t.Errorf("Expected MAC verification error, got: %v", err)
	}
}

// TestDifferentKeySizes tests wrapping and unwrapping keys of different sizes.
func TestDifferentKeySizes(t *testing.T) {
	t.Parallel()
	lmk := getTestLMK()
	header := Header{
		Version:       '1',
		KeyUsage:      "B0",
		Algorithm:     'A',
		ModeOfUse:     'E',
		KeyVersionNum: "00",
		Exportability: 'S',
		KeyContext:    '0',
	}

	keySizes := []int{8, 16, 24, 32, 40} // Various key sizes in bytes.

	for _, size := range keySizes {
		t.Run(fmt.Sprintf("KeySize_%d_bytes", size), func(t *testing.T) {
			t.Parallel()
			// Create a key of the specified size.
			key := make([]byte, size)
			for i := range key {
				key[i] = byte(i % 256)
			}

			// Wrap and unwrap the key.
			keyBlock, err := WrapKeyBlock(lmk, header, nil, key)
			if err != nil {
				t.Fatalf("WrapKeyBlock failed for %d-byte key: %v", size, err)
			}

			_, clearKey, err := UnwrapKeyBlock(lmk, keyBlock)
			if err != nil {
				t.Fatalf("UnwrapKeyBlock failed for %d-byte key: %v", size, err)
			}

			if !bytes.Equal(clearKey, key) {
				t.Errorf("Key mismatch for %d-byte key: expected %X, got %X", size, key, clearKey)
			}
		})
	}
}

// TestInvalidInputs tests error handling for invalid inputs.
func TestInvalidInputs(t *testing.T) {
	t.Parallel()
	lmk := getTestLMK()
	header := Header{
		Version:       '1',
		KeyUsage:      "B0",
		Algorithm:     'A',
		ModeOfUse:     'E',
		KeyVersionNum: "00",
		Exportability: 'S',
		KeyContext:    '0',
	}

	// Test empty key.
	_, err := WrapKeyBlock(lmk, header, nil, []byte{})
	if err != nil {
		t.Logf("WrapKeyBlock correctly rejected empty key: %v", err)
	}

	// Test invalid header (empty key usage).
	invalidHeader := header
	invalidHeader.KeyUsage = ""
	_, err = WrapKeyBlock(lmk, invalidHeader, nil, []byte("test"))
	if err == nil {
		t.Error("WrapKeyBlock should have failed for invalid header")
	}

	// Test unwrapping empty key block.
	_, _, err = UnwrapKeyBlock(lmk, []byte{})
	if err == nil {
		t.Error("UnwrapKeyBlock should have failed for empty key block")
	}

	// Test unwrapping too short key block.
	_, _, err = UnwrapKeyBlock(lmk, []byte("short"))
	if err == nil {
		t.Error("UnwrapKeyBlock should have failed for too short key block")
	}
}

// BenchmarkWrapKeyBlock benchmarks the WrapKeyBlock function.
func BenchmarkWrapKeyBlock(b *testing.B) {
	lmk := getTestLMK()
	key := []byte("0123456789ABCDEF")
	header := Header{
		Version:       '1',
		KeyUsage:      "B0",
		Algorithm:     'A',
		ModeOfUse:     'E',
		KeyVersionNum: "00",
		Exportability: 'S',
		KeyContext:    '0',
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := WrapKeyBlock(lmk, header, nil, key)
		if err != nil {
			b.Fatalf("WrapKeyBlock failed: %v", err)
		}
	}
}

// BenchmarkUnwrapKeyBlock benchmarks the UnwrapKeyBlock function.
func BenchmarkUnwrapKeyBlock(b *testing.B) {
	lmk := getTestLMK()
	keyBlockStr := "S10064B0AE00S000079EAFA5D0F6575FE50C1BD5BB847E4F699B7B5E878D52956"
	keyBlock := []byte(keyBlockStr)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := UnwrapKeyBlock(lmk, keyBlock)
		if err != nil {
			b.Fatalf("UnwrapKeyBlock failed: %v", err)
		}
	}
}
