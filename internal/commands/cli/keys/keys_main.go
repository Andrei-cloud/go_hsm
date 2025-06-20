// Package keys provides key management commands.
package keys

import (
	"github.com/spf13/cobra"
)

// NewKeysCommand creates the keys command group.
func NewKeysCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Key generation and import operations",
		Long: `Key generation and import operations for the HSM.
This command provides subcommands for generating random keys and importing clear keys
under Local Master Keys (LMK) with proper validation and parity checking.`,
	}

	// Add subcommands.
	cmd.AddCommand(newGenerateKeyCommand())
	cmd.AddCommand(newImportKeyCommand())
	cmd.AddCommand(newCheckKeyCommand())
	cmd.AddCommand(newTypesCommand())

	return cmd
}
