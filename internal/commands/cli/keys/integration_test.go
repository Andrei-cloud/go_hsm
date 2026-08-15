package keys

import (
	"encoding/hex"
	"testing"

	"github.com/andrei-cloud/go_hsm/pkg/keyblocklmk"
)

func TestKeyBlockWrapIntegration(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		clearKey []byte
		header   keyblocklmk.Header
	}{
		{
			name:     "AES128Standard",
			clearKey: mustDecodeHex(t, "0123456789ABCDEF"),
			header: keyblocklmk.Header{
				Version:        '1',
				KeyUsage:       "G0",
				Algorithm:      'A',
				ModeOfUse:      'N',
				KeyVersionNum:  "05",
				Exportability:  'S',
				OptionalBlocks: 0,
				KeyContext:     0,
			},
		},
		{
			name: "AES256DifferentHeader",
			clearKey: mustDecodeHex(t,
				"0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
			),
			header: keyblocklmk.Header{
				Version:        '1',
				KeyUsage:       "C0",
				Algorithm:      'A',
				ModeOfUse:      'E',
				KeyVersionNum:  "10",
				Exportability:  'N',
				OptionalBlocks: 0,
				KeyContext:     1,
			},
		},
	}

	for _, tc := range testCases {
		tc := tc // capture loop variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			// Wrap key block.
			keyBlock, err := keyblocklmk.WrapKeyBlock(
				keyblocklmk.DefaultTestAESLMK,
				tc.header,
				nil,
				tc.clearKey,
			)
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

			// Additional structural checks.
			if len(keyBlock) < 1+16+16 { // 'S' + 16 header + at least 16 hex for MAC
				t.Errorf("key block too short: got %d bytes", len(keyBlock))
			}

			// Ensure the key block contains only valid characters (ASCII for header, hex for data).
			for i, b := range keyBlock[1:] { // Skip 'S'
				if b < 32 || b > 126 {
					t.Errorf("invalid character at position %d: %d", i+1, b)
				}
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
			if unwrappedHeader.Version != tc.header.Version {
				t.Errorf(
					"version mismatch: expected '%c', got '%c'",
					tc.header.Version,
					unwrappedHeader.Version,
				)
			}

			if unwrappedHeader.KeyUsage != tc.header.KeyUsage {
				t.Errorf(
					"key usage mismatch: expected '%s', got '%s'",
					tc.header.KeyUsage,
					unwrappedHeader.KeyUsage,
				)
			}

			if unwrappedHeader.KeyVersionNum != tc.header.KeyVersionNum {
				t.Errorf(
					"key version mismatch: expected '%s', got '%s'",
					tc.header.KeyVersionNum,
					unwrappedHeader.KeyVersionNum,
				)
			}

			if unwrappedHeader.Algorithm != tc.header.Algorithm {
				t.Errorf(
					"algorithm mismatch: expected '%c', got '%c'",
					tc.header.Algorithm,
					unwrappedHeader.Algorithm,
				)
			}

			if unwrappedHeader.ModeOfUse != tc.header.ModeOfUse {
				t.Errorf(
					"mode of use mismatch: expected '%c', got '%c'",
					tc.header.ModeOfUse,
					unwrappedHeader.ModeOfUse,
				)
			}

			if unwrappedHeader.Exportability != tc.header.Exportability {
				t.Errorf(
					"exportability mismatch: expected '%c', got '%c'",
					tc.header.Exportability,
					unwrappedHeader.Exportability,
				)
			}

			if unwrappedHeader.OptionalBlocks != tc.header.OptionalBlocks {
				t.Errorf(
					"optional blocks mismatch: expected %d, got %d",
					tc.header.OptionalBlocks,
					unwrappedHeader.OptionalBlocks,
				)
			}

			if unwrappedHeader.KeyContext != tc.header.KeyContext {
				t.Errorf(
					"key context mismatch: expected %d, got %d",
					tc.header.KeyContext,
					unwrappedHeader.KeyContext,
				)
			}

			// Verify key data.
			if hex.EncodeToString(unwrappedKey) != hex.EncodeToString(tc.clearKey) {
				t.Errorf("key data mismatch: expected '%s', got '%s'",
					hex.EncodeToString(tc.clearKey), hex.EncodeToString(unwrappedKey))
			}

			// Validate key sizes.
			if len(unwrappedKey) != len(tc.clearKey) {
				t.Errorf(
					"unwrapped key length mismatch: expected %d, got %d",
					len(tc.clearKey),
					len(unwrappedKey),
				)
			}

			// Log expected key block length for debugging.
			t.Logf(
				"Expected key size: %d bytes, Key block length: %d bytes",
				len(tc.clearKey),
				len(keyBlock),
			)
		})
	}

	t.Run("InvalidLMK", func(t *testing.T) {
		t.Parallel()
		clearKey := mustDecodeHex(t, "0123456789ABCDEF")
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
		keyBlock, err := keyblocklmk.WrapKeyBlock(
			keyblocklmk.DefaultTestAESLMK,
			header,
			nil,
			clearKey,
		)
		if err != nil {
			t.Fatalf("failed to create key block for error test: %v", err)
		}
		invalidLMK := make([]byte, 32)
		for i := range invalidLMK {
			invalidLMK[i] = 0xFF
		}
		_, _, err = keyblocklmk.UnwrapKeyBlock(invalidLMK, keyBlock)
		if err == nil {
			t.Error("expected error when unwrapping with invalid LMK")
		}
	})

	t.Run("TamperedKeyBlock", func(t *testing.T) {
		t.Parallel()
		clearKey := mustDecodeHex(t, "0123456789ABCDEF")
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
		keyBlock, err := keyblocklmk.WrapKeyBlock(
			keyblocklmk.DefaultTestAESLMK,
			header,
			nil,
			clearKey,
		)
		if err != nil {
			t.Fatalf("failed to create key block for error test: %v", err)
		}
		tamperedKeyBlock := make([]byte, len(keyBlock))
		copy(tamperedKeyBlock, keyBlock)
		// Tamper with the MAC by modifying multiple bytes in the hex-encoded MAC at the end.
		macStart := len(tamperedKeyBlock) - 16 // Assuming 16 hex chars for 8-byte MAC
		if macStart > 0 {
			for i := 0; i < 4 && macStart+i < len(tamperedKeyBlock); i++ {
				tamperedKeyBlock[macStart+i] ^= 0x01
			}
		}
		_, _, err = keyblocklmk.UnwrapKeyBlock(keyblocklmk.DefaultTestAESLMK, tamperedKeyBlock)
		if err == nil {
			t.Error("expected error when unwrapping tampered key block")
		}
	})

	t.Run("InvalidHeader", func(t *testing.T) {
		t.Parallel()
		clearKey := mustDecodeHex(t, "0123456789ABCDEF")
		invalidHeader := keyblocklmk.Header{
			Version:        '1',
			KeyUsage:       "TOOLONG", // More than 2 chars
			Algorithm:      'A',
			ModeOfUse:      'N',
			KeyVersionNum:  "05",
			Exportability:  'S',
			OptionalBlocks: 0,
			KeyContext:     0,
		}
		_, err := keyblocklmk.WrapKeyBlock(
			keyblocklmk.DefaultTestAESLMK,
			invalidHeader,
			nil,
			clearKey,
		)
		if err == nil {
			t.Error("expected error when wrapping with invalid header")
		}
	})
}

func mustDecodeHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode hex: %v", err)
	}

	return b
}
