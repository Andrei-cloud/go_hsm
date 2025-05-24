// Package cli contains utilities for CLI operations.
package pinblock

import (
	"fmt"
	"io"
	"os"
	"sort"
	"text/tabwriter"
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
func PrintSupportedFormats(writers ...any) {
	formats := GetSupportedPinBlockFormats()
	codes := make([]string, 0, len(formats))
	for code := range formats {
		codes = append(codes, code)
	}
	sort.Strings(codes)
	var output io.Writer = os.Stdout
	if len(writers) > 0 && writers[0] != nil {
		if w, ok := writers[0].(io.Writer); ok {
			output = w
		}
	}
	// Use tabwriter only for files, otherwise print directly for buffers (test).
	if _, ok := output.(*os.File); ok {
		w := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "format\tdescription") //nolint:errcheck
		for _, code := range codes {
			fmt.Fprintf(w, "%s\t%s\n", code, formats[code]) //nolint:errcheck
		}
		w.Flush() //nolint:errcheck
	} else {
		fmt.Fprintln(output, "format\tdescription") //nolint:errcheck
		for _, code := range codes {
			fmt.Fprintf(output, "%s\t%s\n", code, formats[code]) //nolint:errcheck
		}
	}
}
