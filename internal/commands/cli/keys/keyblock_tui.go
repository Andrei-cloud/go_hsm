package keys

import (
	"fmt"
	"strconv"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/andrei-cloud/go_hsm/pkg/keyblocklmk"
)

const (
	fieldTypeRadio = iota
	fieldTypeNumeric
)

type option struct {
	value       string
	description string
}

type fieldConfig struct {
	name         string
	description  string
	fieldType    int
	options      []option // For radio fields.
	selected     int      // For radio fields.
	numericValue string   // For numeric fields.
	minValue     int      // For numeric fields.
	maxValue     int      // For numeric fields.
	digits       int      // For numeric fields (zero-padding).
}

type keyBlockHeaderModel struct {
	header       keyblocklmk.Header
	currentField int
	fields       []fieldConfig
	done         bool
	cancelled    bool
}

// newKeyBlockHeaderModel creates a new TUI model for configuring key block headers.
func newKeyBlockHeaderModel() keyBlockHeaderModel {
	fields := []fieldConfig{
		{
			name:        "Version",
			description: "Key Block Version",
			fieldType:   fieldTypeRadio,
			options: []option{
				{"0", "Protected by 3-DES key"},
				{"1", "Protected by AES key"},
			},
			selected: 1, // Default to AES.
		},
		{
			name:        "KeyUsage",
			description: "Key Usage",
			fieldType:   fieldTypeRadio,
			options: []option{
				// B - Base Derivation Keys.
				{"B0", "Base Derivation Key (BDK)"},
				{"B1", "DUKPT Initial Key (IKEY)"},
				{"B2", "Base Key Variant"},

				// C - Card Verification.
				{"C0", "Card Verification Key"},

				// D - Data Encryption.
				{"D0", "Data Encryption Key (Generic)"},
				{"D1", "Data Encryption Key (DEK)"},
				{"D2", "Data Encryption Key (TDEA)"},

				// E - EMV/Chip Keys.
				{"E0", "EMV/Chip Master Key: Application Cryptogram (MKAC)"},
				{"E1", "EMV/Chip Master Key: Secure Messaging Confidentiality (MKSMC)"},
				{"E2", "EMV/Chip Master Key: Secure Messaging Integrity (MKSMI)"},
				{"E3", "EMV/Chip Master Key: Data Authentication Code (MKDAC)"},
				{"E4", "EMV/Chip Master Key: Dynamic Numbers (MKDN)"},
				{"E5", "EMV/Chip Master Key: Card Personalization"},
				{"E6", "EMV/Chip Master Key: Other"},

				// G - General Purpose.
				{"G0", "General Purpose Key"},

				// I - Initialization Vector.
				{"I0", "Initialization Value"},

				// K - Key Encryption/Wrapping.
				{"K0", "Key Encryption/Wrapping Key (Generic)"},
				{"K1", "Key Encryption Key (KEK)"},
				{"K2", "Key Wrapping Key"},
				{"K3", "Key Block Protection Key"},

				// M - Message Authentication Code.
				{"M0", "ISO 16609 MAC algorithm 1 (using 3-DES)"},
				{"M1", "ISO 9797-1 MAC algorithm 1"},
				{"M2", "ISO 9797-1 MAC algorithm 2"},
				{"M3", "ISO 9797-1 MAC algorithm 3"},
				{"M4", "ISO 9797-1 MAC algorithm 4"},
				{"M5", "AES CMAC"},
				{"M6", "HMAC key"},
				{"M7", "ISO 9797-1 MAC algorithm 5"},
				{"M8", "ISO 9797-1 MAC algorithm 6"},

				// P - PIN Encryption.
				{"P0", "PIN Encryption Key (Generic)"},
				{"P1", "PIN Encryption Key (IBM Format)"},

				// S - Signature Keys.
				{"S0", "Asymmetric key for digital signature"},
				{"S1", "Asymmetric key pair for CA use"},
				{"S2", "Asymmetric key for non-repudiation"},

				// T - Transport/Transfer.
				{"T0", "Transport Key"},
				{"T1", "Terminal Master Key (TMK)"},

				// V - PIN Verification.
				{"V0", "PIN Verification Key (Generic)"},
				{"V1", "PIN Verification Key (IBM 3624 algorithm)"},
				{"V2", "PIN Verification Key (Visa PVV algorithm)"},
				{"V3", "PIN Verification Key (X9.8, ANSIX9.24, Supplement)"},
				{"V4", "PIN Verification Key (X9.132, algorithm 1)"},
				{"V5", "PIN Verification Key (X9.132, algorithm 2)"},

				// X - Key Agreement.
				{"X0", "Key Agreement Key"},
				{"X1", "Asymmetric Key Agreement Key"},

				// Y - Asymmetric Key Transport.
				{"Y0", "Asymmetric key for key transport"},
			},
			selected: 12, // Default to K0 (Key Encryption/Wrapping Key).
		},
		{
			name:        "Algorithm",
			description: "Cryptographic Algorithm",
			fieldType:   fieldTypeRadio,
			options: []option{
				{"A", "AES"},
				{"D", "DES"},
				{"E", "Elliptic Curve (future reference)"},
				{"H", "HMAC"},
				{"R", "RSA"},
				{"S", "DSA (future reference)"},
				{"T", "Triple DES"},
			},
			selected: 0, // Default to AES.
		},
		{
			name:        "ModeOfUse",
			description: "Mode of Use",
			fieldType:   fieldTypeRadio,
			options: []option{
				{"B", "Both Encrypt and Decrypt"},
				{"C", "MAC Calculation (Both Generate and Verify)"},
				{"D", "Decrypt Only"},
				{"E", "Encrypt Only"},
				{"G", "MAC Generate Only"},
				{"N", "No special restrictions"},
				{"S", "Digital Signature Generation Only"},
				{"V", "Digital Signature Verification Only"},
				{"X", "Key Derivation Only"},
			},
			selected: 5, // Default to No restrictions.
		},
		{
			name:         "KeyVersionNum",
			description:  "Key Version Number (00-99, or 'c1'-'c9' for components)",
			fieldType:    fieldTypeNumeric,
			numericValue: "00",
			minValue:     0,
			maxValue:     99,
			digits:       2,
		},
		{
			name:        "Exportability",
			description: "Key Exportability",
			fieldType:   fieldTypeRadio,
			options: []option{
				{"E", "Exportable in a trusted key block"},
				{"N", "Non-exportable"},
				{"S", "Sensitive - exportable in trusted key block with authentication"},
			},
			selected: 2, // Default to Sensitive.
		},
	}

	return keyBlockHeaderModel{
		header: keyblocklmk.Header{
			Version:        '1',
			KeyUsage:       "K0",
			Algorithm:      'A',
			ModeOfUse:      'N',
			KeyVersionNum:  "00",
			Exportability:  'S',
			OptionalBlocks: 0,
			KeyContext:     0,
		},
		currentField: 0,
		fields:       fields,
	}
}

// Init initializes the model.
func (m keyBlockHeaderModel) Init() tea.Cmd {
	return nil
}

// Update handles messages and updates the model state.
func (m keyBlockHeaderModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		currentField := &m.fields[m.currentField]

		switch msg.String() {
		case "ctrl+c", "q":
			m.cancelled = true

			return m, tea.Quit
		case "enter":
			// Update header with selected values.
			m.updateHeaderFromSelection()
			if m.currentField >= len(m.fields)-1 {
				m.done = true

				return m, tea.Quit
			}
			m.currentField++
		case "tab":
			// Move to next field.
			if m.currentField < len(m.fields)-1 {
				m.currentField++
			}
		case "shift+tab":
			// Move to previous field.
			if m.currentField > 0 {
				m.currentField--
			}
		case "up", "k":
			if currentField.fieldType == fieldTypeRadio {
				if currentField.selected > 0 {
					currentField.selected--
				}
			} else if currentField.fieldType == fieldTypeNumeric {
				m.incrementNumericValue(1)
			}
		case "down", "j":
			if currentField.fieldType == fieldTypeRadio {
				maxIdx := len(currentField.options) - 1
				if currentField.selected < maxIdx {
					currentField.selected++
				}
			} else if currentField.fieldType == fieldTypeNumeric {
				m.decrementNumericValue(1)
			}
		case "backspace":
			if currentField.fieldType == fieldTypeNumeric {
				m.handleBackspace()
			}
		default:
			// Handle numeric input for numeric fields.
			if currentField.fieldType == fieldTypeNumeric && len(msg.String()) == 1 {
				if char := msg.String()[0]; char >= '0' && char <= '9' {
					m.handleNumericInput(char)
				}
			}
		}
	}

	return m, nil
}

// incrementNumericValue increases the numeric value by the specified amount.
func (m *keyBlockHeaderModel) incrementNumericValue(amount int) {
	currentField := &m.fields[m.currentField]
	if currentField.fieldType != fieldTypeNumeric {
		return
	}

	currentValue := m.parseNumericValue(currentField.numericValue)
	newValue := currentValue + amount
	if newValue <= currentField.maxValue {
		currentField.numericValue = m.formatNumericValue(newValue, currentField.digits)
	}
}

// decrementNumericValue decreases the numeric value by the specified amount.
func (m *keyBlockHeaderModel) decrementNumericValue(amount int) {
	currentField := &m.fields[m.currentField]
	if currentField.fieldType != fieldTypeNumeric {
		return
	}

	currentValue := m.parseNumericValue(currentField.numericValue)
	newValue := currentValue - amount
	if newValue >= currentField.minValue {
		currentField.numericValue = m.formatNumericValue(newValue, currentField.digits)
	}
}

// handleNumericInput processes direct numeric character input.
func (m *keyBlockHeaderModel) handleNumericInput(char byte) {
	currentField := &m.fields[m.currentField]
	if currentField.fieldType != fieldTypeNumeric {
		return
	}

	// Remove leading zeros and append new digit.
	currentValue := strings.TrimLeft(currentField.numericValue, "0")
	if currentValue == "" {
		currentValue = "0"
	}

	newValueStr := currentValue + string(char)
	newValue := m.parseNumericValue(newValueStr)

	if newValue >= currentField.minValue && newValue <= currentField.maxValue {
		currentField.numericValue = m.formatNumericValue(newValue, currentField.digits)
	}
}

// handleBackspace removes the last digit from the numeric input.
func (m *keyBlockHeaderModel) handleBackspace() {
	currentField := &m.fields[m.currentField]
	if currentField.fieldType != fieldTypeNumeric {
		return
	}

	if len(currentField.numericValue) > 0 {
		// Remove last character and reformat.
		valueStr := strings.TrimLeft(currentField.numericValue, "0")
		if len(valueStr) <= 1 {
			currentField.numericValue = m.formatNumericValue(0, currentField.digits)
		} else {
			valueStr = valueStr[:len(valueStr)-1]
			newValue := m.parseNumericValue(valueStr)
			currentField.numericValue = m.formatNumericValue(newValue, currentField.digits)
		}
	}
}

// parseNumericValue converts a string to an integer.
func (m *keyBlockHeaderModel) parseNumericValue(value string) int {
	if value == "" {
		return 0
	}

	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0
	}

	return parsed
}

// formatNumericValue formats an integer with leading zeros.
func (m *keyBlockHeaderModel) formatNumericValue(value, digits int) string {
	return fmt.Sprintf("%0*d", digits, value)
}

// updateHeaderFromSelection updates the header struct with currently selected values.
func (m *keyBlockHeaderModel) updateHeaderFromSelection() {
	for i, field := range m.fields {
		switch field.name {
		case "Version":
			selectedOption := field.options[field.selected]
			m.header.Version = selectedOption.value[0]
		case "KeyUsage":
			selectedOption := field.options[field.selected]
			m.header.KeyUsage = selectedOption.value
		case "Algorithm":
			selectedOption := field.options[field.selected]
			m.header.Algorithm = selectedOption.value[0]
		case "ModeOfUse":
			selectedOption := field.options[field.selected]
			m.header.ModeOfUse = selectedOption.value[0]
		case "KeyVersionNum":
			m.header.KeyVersionNum = field.numericValue
		case "Exportability":
			selectedOption := field.options[field.selected]
			m.header.Exportability = selectedOption.value[0]
		}
		m.fields[i] = field
	}
}

// View renders the current state of the model.
func (m keyBlockHeaderModel) View() string {
	if m.done {
		return "Key block header configured successfully!\n"
	}

	if m.cancelled {
		return "Operation cancelled.\n"
	}

	s := "Configure Key Block Header\n"
	s += strings.Repeat("=", 50) + "\n\n"

	// Show progress.
	s += fmt.Sprintf("Field %d of %d\n\n", m.currentField+1, len(m.fields))

	// Show current field.
	currentField := m.fields[m.currentField]
	s += fmt.Sprintf("▶ %s: %s\n\n", currentField.name, currentField.description)

	if currentField.fieldType == fieldTypeRadio {
		// Show radio options for current field only.
		for j, option := range currentField.options {
			selector := "  ○ "
			if j == currentField.selected {
				selector = "  ● "
			}
			s += fmt.Sprintf("%s%s - %s\n", selector, option.value, option.description)
		}
	} else if currentField.fieldType == fieldTypeNumeric {
		// Show numeric input.
		s += fmt.Sprintf("  [ %s ] (Range: %02d-%02d)\n",
			currentField.numericValue, currentField.minValue, currentField.maxValue)
		s += "  Type digits, use ↑/↓ to increment/decrement, Backspace to delete\n"
	}

	s += "\n"

	// Show summary of completed fields.
	if m.currentField > 0 {
		s += "Completed fields:\n"
		for i := 0; i < m.currentField; i++ {
			field := m.fields[i]
			if field.fieldType == fieldTypeRadio {
				selectedOption := field.options[field.selected]
				s += fmt.Sprintf("  %s: %s\n", field.name, selectedOption.value)
			} else if field.fieldType == fieldTypeNumeric {
				s += fmt.Sprintf("  %s: %s\n", field.name, field.numericValue)
			}
		}
		s += "\n"
	}

	s += "Navigation:\n"
	s += "  ↑/↓ or j/k: Select option or increment/decrement value\n"
	s += "  Tab/Shift+Tab: Next/Previous field\n"
	s += "  Enter: Confirm and continue\n"
	if currentField.fieldType == fieldTypeNumeric {
		s += "  0-9: Direct numeric input\n"
		s += "  Backspace: Delete digit\n"
	}
	s += "  q or Ctrl+C: Quit\n"

	return s
}

// runKeyBlockHeaderTUI starts the interactive TUI for key block header configuration.
func runKeyBlockHeaderTUI() (keyblocklmk.Header, bool, error) {
	model := newKeyBlockHeaderModel()

	p := tea.NewProgram(model)
	finalModel, err := p.Run()
	if err != nil {
		return keyblocklmk.Header{}, false, err
	}

	m := finalModel.(keyBlockHeaderModel)
	m.updateHeaderFromSelection() // Ensure final state is captured.

	return m.header, !m.cancelled, nil
}
