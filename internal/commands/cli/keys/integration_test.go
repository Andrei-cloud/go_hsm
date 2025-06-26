package keys

import (
	"encoding/hex"
	"testing"

	"github.com/andrei-cloud/go_hsm/pkg/keyblocklmk"
)

func TestKeyBlockWrapIntegration(t *testing.T) {
	// Test key block wrapping with a configured header.
	clearKey, err := hex.DecodeString("0123456789ABCDEF")
	if err != nil {
		t.Fatalf("failed to decode test key: %v", err)
	}

	header := keyblocklmk.Header{
		Version:        '1',
		KeyUsage:       "G0",
		Algorithm:      'A',
		ModeOfUse:      'N',
		KeyVersionNum:  "05",
		Exportability:  'S',
		OptionalBlocks: 0,
		KeyContext:     0,
	}

	// Wrap key block.
	keyBlock, err := keyblocklmk.WrapKeyBlock(keyblocklmk.DefaultTestAESLMK, header, nil, clearKey)
	if err != nil {
		t.Fatalf("failed to wrap key block: %v", err)
	}

	// Verify key block was created.
	if len(keyBlock) == 0 {
		t.Error("expected non-empty key block")
	}

	// Verify it starts with 'S' (format identifier).
	if keyBlock[0] != 'S' {
		t.Errorf("expected key block to start with 'S', got '%c'", keyBlock[0])
	}

	// Test unwrapping to verify round-trip.
	unwrappedHeader, unwrappedKey, err := keyblocklmk.UnwrapKeyBlock(
		keyblocklmk.DefaultTestAESLMK,
		keyBlock,
	)
	if err != nil {
		t.Fatalf("failed to unwrap key block: %v", err)
	}

	// Verify header fields.
	if unwrappedHeader.Version != header.Version {
		t.Errorf(
			"version mismatch: expected '%c', got '%c'",
			header.Version,
			unwrappedHeader.Version,
		)
	}

	if unwrappedHeader.KeyUsage != header.KeyUsage {
		t.Errorf(
			"key usage mismatch: expected '%s', got '%s'",
			header.KeyUsage,
			unwrappedHeader.KeyUsage,
		)
	}

	if unwrappedHeader.KeyVersionNum != header.KeyVersionNum {
		t.Errorf(
			"key version mismatch: expected '%s', got '%s'",
			header.KeyVersionNum,
			unwrappedHeader.KeyVersionNum,
		)
	}

	// Verify key data.
	if hex.EncodeToString(unwrappedKey) != hex.EncodeToString(clearKey) {
		t.Errorf("key data mismatch: expected '%s', got '%s'",
			hex.EncodeToString(clearKey), hex.EncodeToString(unwrappedKey))
	}

	t.Logf("Key block created successfully: S%s", hex.EncodeToString(keyBlock[1:]))
	t.Logf("Header - Version: %c, KeyUsage: %s, KeyVersionNum: %s",
		unwrappedHeader.Version, unwrappedHeader.KeyUsage, unwrappedHeader.KeyVersionNum)
}
