// Package cli contains utilities for CLI operations.
package cli

import (
	"fmt"
)

// GetSupportedPinBlockFormats returns a map of Thales format codes to readable format descriptions.
func GetSupportedPinBlockFormats() map[string]string {
	return map[string]string{
		"01": "ISO 9564-1 Format 0 (ANSI X9.8)",
		"02": "Docutel Format",
		"03": "Diebold/IBM 3624 Format",
		"04": "PLUS Network Format",
		"05": "ISO 9564-1 Format 1",
		"34": "ISO 9564-1 Format 2",
		"35": "Mastercard Pay Now & Pay Later Format",
		"41": "Visa PIN-only Change Format",
		"42": "Visa Old+New PIN Change Format",
		"47": "ISO 9564-1 Format 3",
		"48": "ISO 9564-1 Format 4",
	}
}

// PrintSupportedFormats prints the supported PIN block formats in a readable format.
func PrintSupportedFormats() {
	formats := GetSupportedPinBlockFormats()
	fmt.Println("Supported PIN block formats:")
	fmt.Println("----------------------------")
	for code, desc := range formats {
		fmt.Printf("%s: %s\n", code, desc)
	}
}
