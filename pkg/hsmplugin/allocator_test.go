package hsmplugin

import "testing"

// TestResetAllocator verifies that ResetAllocator sets nextPtr to the initial offset.
func TestResetAllocator(t *testing.T) {
	ResetAllocator()

	ptr := Alloc(1)
	if ptr != 8 {
		t.Errorf("expected ptr 8, got %d", ptr)
	}
}

// TestAllocAlignment verifies that Alloc returns 8-byte aligned pointers.
func TestAllocAlignment(t *testing.T) {
	ResetAllocator()

	ptr1 := Alloc(5)

	ptr2 := Alloc(3)

	if ptr2%8 != 0 {
		t.Errorf("expected 8-byte aligned, got %d", ptr2)
	}

	if ptr2 <= ptr1 {
		t.Errorf("expected ptr2 > ptr1, got %d <= %d", ptr2, ptr1)
	}
}
