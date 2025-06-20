package keyblocklmk_test

import (
	"bytes"
	"testing"

	"github.com/andrei-cloud/go_hsm/pkg/keyblocklmk"
)

// TestWrapUnwrapRoundTrip verifies that wrapping and then unwrapping returns the original key and header.
func TestWrapUnwrapRoundTrip(t *testing.T) {
	t.Parallel()

	// sample header
	header := keyblocklmk.Header{
		Version:        'D',
		KeyUsage:       "B0",
		Algorithm:      'A',
		ModeOfUse:      'E',
		KeyVersionNum:  "01",
		Exportability:  'E',
		OptionalBlocks: 0,
		KeyContext:     0,
	}

	// sample key
	plainKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	// wrap under default LMK, format 'R'
	block, err := keyblocklmk.WrapKeyBlock(
		keyblocklmk.DefaultTestAESLMK,
		header,
		nil,
		plainKey,
		'R',
	)
	if err != nil {
		t.Fatalf("WrapKeyBlock failed: %v", err)
	}

	// unwrap
	unwrappedHeader, plaintext, err := keyblocklmk.UnwrapKeyBlock(
		keyblocklmk.DefaultTestAESLMK,
		block,
	)
	if err != nil {
		t.Fatalf("UnwrapKeyBlock failed: %v", err)
	}

	// compare header fields
	if *unwrappedHeader != header {
		t.Errorf("header mismatch: got %+v, want %+v", unwrappedHeader, header)
	}

	// compare key
	if !bytes.Equal(plaintext, plainKey) {
		t.Errorf("key mismatch: got %x, want %x", plaintext, plainKey)
	}
}

// TestWrapUnwrapWithOptionalBlocks verifies optional header blocks are preserved.
func TestWrapUnwrapWithOptionalBlocks(t *testing.T) {
	t.Parallel()

	// header with one optional block count
	header := keyblocklmk.Header{
		Version:        'D',
		KeyUsage:       "B1",
		Algorithm:      'A',
		ModeOfUse:      'B',
		KeyVersionNum:  "02",
		Exportability:  'N',
		OptionalBlocks: 1,
		KeyContext:     0,
	}

	opt := keyblocklmk.OptionalBlock{Tag: "0A", Value: []byte{0xAA, 0xBB}}
	plainKey := []byte{0x10, 0x20, 0x30}

	block, err := keyblocklmk.WrapKeyBlock(
		keyblocklmk.DefaultTestAESLMK,
		header,
		[]keyblocklmk.OptionalBlock{opt},
		plainKey,
		'R',
	)
	if err != nil {
		t.Fatalf("WrapKeyBlock with optional failed: %v", err)
	}

	unHdr, plaintext, err := keyblocklmk.UnwrapKeyBlock(keyblocklmk.DefaultTestAESLMK, block)
	if err != nil {
		t.Fatalf("UnwrapKeyBlock with optional failed: %v", err)
	}

	if *unHdr != header {
		t.Errorf("header mismatch: got %+v, want %+v", unHdr, header)
	}

	if !bytes.Equal(plaintext, plainKey) {
		t.Errorf("key mismatch: got %x, want %x", plaintext, plainKey)
	}
}

// TestUnwrapTamperedBlock ensures MAC verification fails on tampering.
func TestUnwrapTamperedBlock(t *testing.T) {
	t.Parallel()

	header := keyblocklmk.Header{
		Version:        'D',
		KeyUsage:       "B0",
		Algorithm:      'A',
		ModeOfUse:      'E',
		KeyVersionNum:  "01",
		Exportability:  'E',
		OptionalBlocks: 0,
		KeyContext:     0,
	}
	plainKey := []byte{0xAA, 0xBB}

	block, err := keyblocklmk.WrapKeyBlock(
		keyblocklmk.DefaultTestAESLMK,
		header,
		nil,
		plainKey,
		'R',
	)
	if err != nil {
		t.Fatalf("WrapKeyBlock failed: %v", err)
	}

	// tamper a byte in ciphertext
	block[len(block)/2] ^= 0xFF

	_, _, err = keyblocklmk.UnwrapKeyBlock(keyblocklmk.DefaultTestAESLMK, block)
	if err == nil {
		t.Fatal("UnwrapKeyBlock did not fail on tampering")
	}
}

// TestWrapUnwrapFormatS verifies format 'S' key blocks with 8-byte MAC.
func TestWrapUnwrapFormatS(t *testing.T) {
	t.Parallel()

	header := keyblocklmk.Header{
		Version:        'S', // Format S version
		KeyUsage:       "B0",
		Algorithm:      'A',
		ModeOfUse:      'E',
		KeyVersionNum:  "01",
		Exportability:  'E',
		OptionalBlocks: 0,
		KeyContext:     0,
	}

	plainKey := []byte{0x01, 0x02, 0x03, 0x04, 0x05}

	block, err := keyblocklmk.WrapKeyBlock(
		keyblocklmk.DefaultTestAESLMK,
		header,
		nil,
		plainKey,
		'S',
	)
	if err != nil {
		t.Fatalf("WrapKeyBlock format S failed: %v", err)
	}

	// Verify total block structure for format 'S'
	// Expected: 'S' tag (1 char) + header (16 ASCII chars) + hex-encoded (padded encrypted key + 8-byte MAC)
	// For 5-byte key: 2-byte length + 5-byte key + 9-byte padding = 16 bytes encrypted
	// Binary encrypted + MAC: 16 + 8 = 24 bytes -> ASCII hex: 48 characters
	// Total: 'S' (1) + header (16) + hex-encoded data (48) = 65 characters
	expectedTotal := 1 + 16 + (16+8)*2 // 'S' + header + hex-encoded (encrypted + MAC)
	if len(block) != expectedTotal {
		t.Errorf(
			"format S block has wrong total length: got %d bytes, want %d",
			len(block),
			expectedTotal,
		)
	}

	unHdr, plaintext, err := keyblocklmk.UnwrapKeyBlock(keyblocklmk.DefaultTestAESLMK, block)
	if err != nil {
		t.Fatalf("UnwrapKeyBlock format S failed: %v", err)
	}

	if *unHdr != header {
		t.Errorf("format S header mismatch: got %+v, want %+v", unHdr, header)
	}

	if !bytes.Equal(plaintext, plainKey) {
		t.Errorf("format S key mismatch: got %x, want %x", plaintext, plainKey)
	}
}

// TestWrapUnwrapDifferentKeySizes verifies wrapping keys of different lengths.
func TestWrapUnwrapDifferentKeySizes(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name     string
		keyBytes int
	}{
		{"8-byte DES key", 8},
		{"16-byte AES key", 16},
		{"24-byte 3DES key", 24},
		{"32-byte AES key", 32},
	}

	header := keyblocklmk.Header{
		Version:        'D',
		KeyUsage:       "B0",
		Algorithm:      'A',
		ModeOfUse:      'E',
		KeyVersionNum:  "01",
		Exportability:  'E',
		OptionalBlocks: 0,
		KeyContext:     0,
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			plainKey := make([]byte, tc.keyBytes)
			for i := range plainKey {
				plainKey[i] = byte(i)
			}

			block, err := keyblocklmk.WrapKeyBlock(
				keyblocklmk.DefaultTestAESLMK,
				header,
				nil,
				plainKey,
				'R',
			)
			if err != nil {
				t.Fatalf("WrapKeyBlock failed for %d-byte key: %v", tc.keyBytes, err)
			}

			unHdr, plaintext, err := keyblocklmk.UnwrapKeyBlock(
				keyblocklmk.DefaultTestAESLMK,
				block,
			)
			if err != nil {
				t.Fatalf("UnwrapKeyBlock failed for %d-byte key: %v", tc.keyBytes, err)
			}

			if *unHdr != header {
				t.Errorf(
					"%d-byte key header mismatch: got %+v, want %+v",
					tc.keyBytes,
					unHdr,
					header,
				)
			}

			if !bytes.Equal(plaintext, plainKey) {
				t.Errorf("%d-byte key mismatch: got %x, want %x", tc.keyBytes, plaintext, plainKey)
			}
		})
	}
}

// TestHeaderFieldValidation verifies header field validation.
func TestHeaderFieldValidation(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		header  keyblocklmk.Header
		wantErr bool
	}{
		{
			name: "valid header",
			header: keyblocklmk.Header{
				Version:        'D',
				KeyUsage:       "B0",
				Algorithm:      'A',
				ModeOfUse:      'E',
				KeyVersionNum:  "01",
				Exportability:  'E',
				OptionalBlocks: 0,
				KeyContext:     0,
			},
			wantErr: false,
		},
		{
			name: "invalid key usage length",
			header: keyblocklmk.Header{
				Version:        'D',
				KeyUsage:       "B", // Wrong length
				Algorithm:      'A',
				ModeOfUse:      'E',
				KeyVersionNum:  "01",
				Exportability:  'E',
				OptionalBlocks: 0,
				KeyContext:     0,
			},
			wantErr: true,
		},
		{
			name: "invalid version number length",
			header: keyblocklmk.Header{
				Version:        'D',
				KeyUsage:       "B0",
				Algorithm:      'A',
				ModeOfUse:      'E',
				KeyVersionNum:  "1", // Wrong length
				Exportability:  'E',
				OptionalBlocks: 0,
				KeyContext:     0,
			},
			wantErr: true,
		},
	}

	plainKey := []byte{0x01, 0x02, 0x03}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := keyblocklmk.WrapKeyBlock(
				keyblocklmk.DefaultTestAESLMK,
				tc.header,
				nil,
				plainKey,
				'R',
			)
			if (err != nil) != tc.wantErr {
				t.Errorf("WrapKeyBlock() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

// TestUnwrapErrorConditions verifies error handling during unwrapping.
func TestUnwrapErrorConditions(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name    string
		block   []byte
		wantErr bool
	}{
		{
			name:    "block too short",
			block:   make([]byte, 15), // Less than header size
			wantErr: true,
		},
		{
			name:    "invalid header",
			block:   bytes.Repeat([]byte{0xFF}, 32), // Invalid header format
			wantErr: true,
		},
		{
			name:    "truncated optional block",
			block:   append(make([]byte, 16), 0x01), // Header with optional block but truncated
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		tc := tc // capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, _, err := keyblocklmk.UnwrapKeyBlock(keyblocklmk.DefaultTestAESLMK, tc.block)
			if (err != nil) != tc.wantErr {
				t.Errorf("UnwrapKeyBlock() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
