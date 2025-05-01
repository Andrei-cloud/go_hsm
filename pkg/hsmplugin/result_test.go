package hsmplugin

import (
	"testing"
)

// TestPackResult verifies that PackResult combines pointer and length into a uint64 value.
func TestPackResult(t *testing.T) {
	highIn := uint32(0xDEADBEEF)
	lowIn := uint32(0xFEEDFACE)
	combined := PackResult(highIn, lowIn)

	high := uint32(combined >> 32)
	low := uint32(combined)
	if high != highIn || low != lowIn {
		t.Errorf("expected high=0x%X low=0x%X, got high=0x%X low=0x%X", highIn, lowIn, high, low)
	}
}

// TestWriteError verifies that WriteError returns a packed result with correct pointer and length.
func TestWriteError(t *testing.T) {
	ResetAllocator()

	cmd := "AZ"
	res := WriteError(cmd)
	high := uint32(res >> 32)
	low := uint32(res)
	if low != 4 {
		t.Errorf("expected length 4, got %d", low)
	}
	if high != 8 {
		t.Errorf("expected pointer 8, got %d", high)
	}
}
