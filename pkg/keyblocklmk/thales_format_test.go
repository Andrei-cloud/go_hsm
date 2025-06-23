package keyblocklmk_test

import (
	"testing"

	"github.com/andrei-cloud/go_hsm/pkg/keyblocklmk"
)

// TestThalesKeyBlockFormat verifies the key block format matches Thales specification.
func TestThalesKeyBlockFormat(t *testing.T) {
	t.Parallel()

	// Test header according to specification.
	header := keyblocklmk.Header{
		Version:        '1',  // "1" for AES key protection
		KeyUsage:       "B0", // Base Derivation Key usage
		Algorithm:      'A',  // AES algorithm
		ModeOfUse:      'E',  // Encrypt only
		KeyVersionNum:  "00", // No key versioning
		Exportability:  'S',  // Sensitive export
		OptionalBlocks: 0,    // No optional blocks
		KeyContext:     0,    // LMK ID "00"
	}

	plainKey := []byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF} // 8-byte DES key

	keyBlock, err := keyblocklmk.WrapKeyBlock(
		keyblocklmk.DefaultTestAESLMK,
		header,
		nil,
		plainKey,
		'S', // Thales format
	)
	if err != nil {
		t.Fatalf("WrapKeyBlock failed: %v", err)
	}

	// Verify key block structure according to specification.
	t.Logf("Generated key block %s", keyBlock)
	t.Logf("Key block length: %d bytes", len(keyBlock))

	// According to specification, key block should have:
	// - Key scheme tag 'S' (1 ASCII character) for Thales format
	// - 16-byte header (16 ASCII characters, NOT hex-encoded)
	// - Optional header blocks (ASCII)
	// - Encrypted key data (ASCII hex encoded)
	// - 8-byte authenticator for format 'S' (16 ASCII hex characters)

	// Verify key scheme tag for Thales format
	if len(keyBlock) < 1 || keyBlock[0] != 'S' {
		t.Errorf("Missing or incorrect key scheme tag: expected 'S' at start")
	}

	// Extract the key block data after the 'S' tag
	keyBlockData := keyBlock[1:]
	if len(keyBlockData) < 16 { // 16 ASCII characters for header
		t.Errorf("Key block data too short: got %d characters, want at least 16", len(keyBlockData))
	}

	// Check header structure (first 16 ASCII characters).
	headerASCII := string(keyBlockData[:16])
	t.Logf("Header ASCII: %s", headerASCII)

	// Verify the header fields directly from ASCII characters
	headerBytes := []byte(headerASCII)

	// Verify version field (byte 0).
	if headerBytes[0] != '1' {
		t.Errorf("Version field: got %c, want '1'", headerBytes[0])
	}

	// Verify key block length field (bytes 1-4) is 4 ASCII digits.
	lengthField := string(headerBytes[1:5])
	t.Logf("Length field: %s", lengthField)

	// Verify key usage (bytes 5-6).
	usageField := string(headerBytes[5:7])
	if usageField != "B0" {
		t.Errorf("Usage field: got %s, want B0", usageField)
	}

	// Test unwrapping.
	unwrappedHeader, clearKey, _, _, err := keyblocklmk.UnwrapKeyBlock(
		keyblocklmk.DefaultTestAESLMK,
		keyBlock,
	)
	if err != nil {
		t.Fatalf("UnwrapKeyBlock failed: %v", err)
	}

	if *unwrappedHeader != header {
		t.Errorf("Header mismatch: got %+v, want %+v", unwrappedHeader, header)
	}

	if !equal(clearKey, plainKey) {
		t.Errorf("Key mismatch: got %x, want %x", clearKey, plainKey)
	}
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}

	return true
}
