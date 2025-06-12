// Package keys provides key types command implementation.
package keys

import (
	"fmt"
	"sort"
	"text/tabwriter"

	"github.com/andrei-cloud/go_hsm/pkg/variantlmk"
	"github.com/spf13/cobra"
)

func newTypesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "types",
		Short: "List all supported key types",
		Long: `List all supported key types and their details.
Shows the key type code, name, LMK pair index, and variant ID for each type.
Use --pci flag to show PCI-HSM compliant key types.`,
		RunE: runTypes,
	}

	cmd.Flags().Bool("pci", false, "Show PCI-HSM compliant key types")

	return cmd
}

func runTypes(cmd *cobra.Command, _ []string) error {
	pciMode, _ := cmd.Flags().GetBool("pci")

	var keyTypes map[string]variantlmk.KeyType
	if pciMode {
		keyTypes = variantlmk.KeyTypesPCI
		cmd.Println("PCI-HSM Compliant Key Types:")
	} else {
		keyTypes = variantlmk.KeyTypes
		cmd.Println("Standard Key Types:")
	}

	// Get all key type codes.
	codes := make([]string, 0, len(keyTypes))
	for code := range keyTypes {
		codes = append(codes, code)
	}

	// Sort codes for consistent output.
	sort.Strings(codes)

	// Create and configure tabwriter.
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)

	// Print header.
	if _, err := fmt.Fprintln(w, "Code\tName\tLMK Pair\tVariant"); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if _, err := fmt.Fprintln(w, "----\t----\t--------\t-------"); err != nil {
		return fmt.Errorf("failed to write header separator: %w", err)
	}

	// Print key types in sorted order.
	for _, code := range codes {
		kt := keyTypes[code]
		lmkPairRange := fmt.Sprintf("%d-%d", kt.LMKPair*2, kt.LMKPair*2+1)
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%d\n",
			kt.Code,
			kt.Name,
			lmkPairRange,
			kt.VariantID,
		); err != nil {
			return fmt.Errorf("failed to write key type info: %w", err)
		}
	}

	if err := w.Flush(); err != nil {
		return fmt.Errorf("failed to flush output: %w", err)
	}

	return nil
}
