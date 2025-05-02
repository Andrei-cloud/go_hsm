package hsmplugin

import (
	"testing"
)

// TestPackResult verifies that PackResult combines pointer and length into a uint64 value.
func TestPackResult(t *testing.T) {
	t.Parallel()
	highIn := uint32(0xDEADBEEF)
	lowIn := uint32(0xFEEDFACE)
	combined := PackResult(highIn, lowIn)

	high, low := UnpackResult(combined)
	if high != highIn || low != lowIn {
		t.Errorf("expected high=0x%X low=0x%X, got high=0x%X low=0x%X", highIn, lowIn, high, low)
	}
}

// TestWriteError verifies that WriteError returns a packed result with correct pointer and length.
func TestWriteError(t *testing.T) {
	t.Parallel()

	cmd := "AZ"
	res := WriteError(cmd)
	high, low := UnpackResult(res)
	if low != 4 {
		t.Errorf("expected length 4, got %d", low)
	}
	if high != 0x0 {
		t.Errorf("expected pointer 0, got %d", high)
	}
}
