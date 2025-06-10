package keyblocklmk_test

import (
	"bytes"
	"testing"

	"github.com/andrei-cloud/go_hsm/pkg/keyblocklmk"
)

// TestWrapUnwrapRoundTrip verifies that wrapping and then unwrapping returns the original key and header.
func TestWrapUnwrapRoundTrip(t *testing.T) {
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
	unwrappedHeader, clear, err := keyblocklmk.UnwrapKeyBlock(keyblocklmk.DefaultTestAESLMK, block)
	if err != nil {
		t.Fatalf("UnwrapKeyBlock failed: %v", err)
	}

	// compare header fields
	if *unwrappedHeader != header {
		t.Errorf("header mismatch: got %+v, want %+v", unwrappedHeader, header)
	}

	// compare key
	if !bytes.Equal(clear, plainKey) {
		t.Errorf("key mismatch: got %x, want %x", clear, plainKey)
	}
}

// TestWrapUnwrapWithOptionalBlocks verifies optional header blocks are preserved.
func TestWrapUnwrapWithOptionalBlocks(t *testing.T) {
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

	unHdr, clear, err := keyblocklmk.UnwrapKeyBlock(keyblocklmk.DefaultTestAESLMK, block)
	if err != nil {
		t.Fatalf("UnwrapKeyBlock with optional failed: %v", err)
	}

	if *unHdr != header {
		t.Errorf("header mismatch: got %+v, want %+v", unHdr, header)
	}

	if !bytes.Equal(clear, plainKey) {
		t.Errorf("key mismatch: got %x, want %x", clear, plainKey)
	}
}

// TestUnwrapTamperedBlock ensures MAC verification fails on tampering.
func TestUnwrapTamperedBlock(t *testing.T) {
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

// TestComputeCheckValue verifies default test LMK check value matches known.
func TestComputeCheckValue(t *testing.T) {
	check, err := keyblocklmk.ComputeCheckValue(keyblocklmk.DefaultTestAESLMK)
	if err != nil {
		t.Fatalf("ComputeCheckValue error: %v", err)
	}
	const want = "9D04A0"
	if check != want {
		t.Errorf("check value = %s, want %s", check, want)
	}
}
