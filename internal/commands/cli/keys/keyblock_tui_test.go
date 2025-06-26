package keys

import (
	"testing"
)

func TestKeyBlockHeaderTUI(t *testing.T) {
	// Test that the TUI model initializes correctly.
	model := newKeyBlockHeaderModel()

	// Check initial header values.
	if model.header.Version != '1' {
		t.Errorf("expected Version to be '1', got '%c'", model.header.Version)
	}

	if model.header.KeyUsage != "K0" {
		t.Errorf("expected KeyUsage to be 'K0', got '%s'", model.header.KeyUsage)
	}

	if model.header.Algorithm != 'A' {
		t.Errorf("expected Algorithm to be 'A', got '%c'", model.header.Algorithm)
	}

	if model.header.ModeOfUse != 'N' {
		t.Errorf("expected ModeOfUse to be 'N', got '%c'", model.header.ModeOfUse)
	}

	if model.header.KeyVersionNum != "00" {
		t.Errorf("expected KeyVersionNum to be '00', got '%s'", model.header.KeyVersionNum)
	}

	if model.header.Exportability != 'S' {
		t.Errorf("expected Exportability to be 'S', got '%c'", model.header.Exportability)
	}

	// Test field configuration.
	if len(model.fields) != 6 {
		t.Errorf("expected 6 fields, got %d", len(model.fields))
	}

	// Test the numeric field for KeyVersionNum.
	keyVersionField := model.fields[4] // KeyVersionNum is the 5th field (index 4).
	if keyVersionField.fieldType != fieldTypeNumeric {
		t.Errorf("expected KeyVersionNum field to be numeric type")
	}

	if keyVersionField.numericValue != "00" {
		t.Errorf(
			"expected KeyVersionNum initial value to be '00', got '%s'",
			keyVersionField.numericValue,
		)
	}

	if keyVersionField.minValue != 0 || keyVersionField.maxValue != 99 {
		t.Errorf(
			"expected KeyVersionNum range to be 0-99, got %d-%d",
			keyVersionField.minValue,
			keyVersionField.maxValue,
		)
	}
}

func TestNumericFieldOperations(t *testing.T) {
	model := newKeyBlockHeaderModel()

	// Move to KeyVersionNum field (index 4).
	model.currentField = 4

	// Test increment.
	model.incrementNumericValue(1)
	if model.fields[4].numericValue != "01" {
		t.Errorf(
			"expected value to be '01' after increment, got '%s'",
			model.fields[4].numericValue,
		)
	}

	// Test increment to max.
	model.fields[4].numericValue = "99"
	model.incrementNumericValue(1) // Should not go beyond 99.
	if model.fields[4].numericValue != "99" {
		t.Errorf("expected value to remain '99' at max, got '%s'", model.fields[4].numericValue)
	}

	// Test decrement.
	model.decrementNumericValue(1)
	if model.fields[4].numericValue != "98" {
		t.Errorf(
			"expected value to be '98' after decrement, got '%s'",
			model.fields[4].numericValue,
		)
	}

	// Test decrement to min.
	model.fields[4].numericValue = "00"
	model.decrementNumericValue(1) // Should not go below 00.
	if model.fields[4].numericValue != "00" {
		t.Errorf("expected value to remain '00' at min, got '%s'", model.fields[4].numericValue)
	}

	// Test numeric input.
	model.handleNumericInput('5')
	if model.fields[4].numericValue != "05" {
		t.Errorf(
			"expected value to be '05' after numeric input, got '%s'",
			model.fields[4].numericValue,
		)
	}

	// Test backspace.
	model.handleBackspace()
	if model.fields[4].numericValue != "00" {
		t.Errorf(
			"expected value to be '00' after backspace, got '%s'",
			model.fields[4].numericValue,
		)
	}
}

func TestHeaderUpdate(t *testing.T) {
	model := newKeyBlockHeaderModel()

	// Modify some selections.
	model.fields[0].selected = 0        // Version: "0" (3-DES).
	model.fields[1].selected = 0        // KeyUsage: "B0".
	model.fields[4].numericValue = "15" // KeyVersionNum: "15".

	// Update header from selections.
	model.updateHeaderFromSelection()

	// Check updated values.
	if model.header.Version != '0' {
		t.Errorf("expected Version to be '0', got '%c'", model.header.Version)
	}

	if model.header.KeyUsage != "B0" {
		t.Errorf("expected KeyUsage to be 'B0', got '%s'", model.header.KeyUsage)
	}

	if model.header.KeyVersionNum != "15" {
		t.Errorf("expected KeyVersionNum to be '15', got '%s'", model.header.KeyVersionNum)
	}
}
