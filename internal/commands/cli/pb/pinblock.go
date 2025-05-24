// Package pb provides PIN block related commands.
package pb

import (
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/pinblock"
	"github.com/spf13/cobra"
)

// NewPinBlockCommand creates the pinblock command with subcommands.
func NewPinBlockCommand() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:   "pinblock",
		Short: "PIN block operations",
		Long: `PIN block operations for generating PIN blocks and extracting PINs.
Supports various industry-standard PIN block formats including ISO formats,
Thales formats, and other proprietary formats.`,
		Example: `  # Generate a PIN block
  go_hsm pinblock create --pin 1234 --pan 4111111111111111 --format 01

  # Extract PIN from PIN block
  go_hsm pinblock extract --pinblock 123456789ABCDEF --pan 4111111111111111 --format 01

  # List supported formats
  go_hsm pinblock formats`,
	}

	// Add subcommands.
	createCmd, err := newCreateCommand()
	if err != nil {
		return nil, fmt.Errorf("failed to create 'create' subcommand: %w", err)
	}
	cmd.AddCommand(createCmd)

	extractCmd, err := newExtractCommand()
	if err != nil {
		return nil, fmt.Errorf("failed to create 'extract' subcommand: %w", err)
	}
	cmd.AddCommand(extractCmd)

	cmd.AddCommand(newFormatsCommand())

	return cmd, nil
}

func newCreateCommand() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "Generate a PIN block",
		Long: `Generate a PIN block using specified PIN, PAN, and format code.
The PIN should be 4-12 digits, and the PAN should be a valid card number.
The format code specifies which PIN block format to use (e.g., 01 for ISO Format 0).`,
		Example: `  # Generate ISO Format 0 PIN block
  go_hsm pinblock create --pin 1234 --pan 4111111111111111 --format 01

  # Generate Thales Format 04 (PLUS Network) PIN block
  go_hsm pinblock create --pin 1234 --pan 4111111111111111 --format 04`,
		RunE: runCreate,
	}

	// Add flags.
	cmd.Flags().String("pin", "", "PIN number (4-12 digits)")
	cmd.Flags().String("pan", "", "Primary Account Number (card number)")
	cmd.Flags().String("format", "", "Thales format code (e.g., 01 for ISO 0)")

	// Mark required flags.
	if err := cmd.MarkFlagRequired("pin"); err != nil {
		return nil, fmt.Errorf("failed to mark pin flag as required: %w", err)
	}
	if err := cmd.MarkFlagRequired("pan"); err != nil {
		return nil, fmt.Errorf("failed to mark pan flag as required: %w", err)
	}
	if err := cmd.MarkFlagRequired("format"); err != nil {
		return nil, fmt.Errorf("failed to mark format flag as required: %w", err)
	}

	return cmd, nil
}

func newExtractCommand() (*cobra.Command, error) {
	cmd := &cobra.Command{
		Use:   "extract",
		Short: "Extract PIN from PIN block",
		Long: `Extract the clear PIN from an encrypted PIN block using the specified format.
Requires the PIN block as a hex string, the PAN used during generation,
and the format code that was used to create the PIN block.`,
		Example: `  # Extract PIN from ISO Format 0 PIN block
  go_hsm pinblock extract --pinblock 123456789ABCDEF --pan 4111111111111111 --format 01

  # Extract PIN from Thales Format 04 PIN block
  go_hsm pinblock extract --pinblock ABCDEF123456789 --pan 4111111111111111 --format 04`,
		RunE: runExtract,
	}

	// Add flags.
	cmd.Flags().String("pinblock", "", "PIN block hex string to extract PIN from")
	cmd.Flags().String("pan", "", "Primary Account Number (card number)")
	cmd.Flags().String("format", "", "Thales format code (e.g., 01 for ISO 0)")

	// Mark required flags.
	if err := cmd.MarkFlagRequired("pinblock"); err != nil {
		return nil, fmt.Errorf("failed to mark pinblock flag as required: %w", err)
	}
	if err := cmd.MarkFlagRequired("pan"); err != nil {
		return nil, fmt.Errorf("failed to mark pan flag as required: %w", err)
	}
	if err := cmd.MarkFlagRequired("format"); err != nil {
		return nil, fmt.Errorf("failed to mark format flag as required: %w", err)
	}

	return cmd, nil
}

func newFormatsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "formats",
		Short: "List supported PIN block formats",
		Long: `List all supported PIN block formats with their descriptions.
Shows the format code and a brief description of each supported format.`,
		Example: `  # List all supported formats
  go_hsm pinblock formats`,
		RunE: runFormats,
	}

	return cmd
}

func runCreate(cmd *cobra.Command, _ []string) error {
	pin, _ := cmd.Flags().GetString("pin")
	pan, _ := cmd.Flags().GetString("pan")
	formatCode, _ := cmd.Flags().GetString("format")

	result, err := pinblock.GeneratePinBlock(pin, pan, formatCode)
	if err != nil {
		return err
	}

	cmd.Printf("PIN block generated (format %s): %s\n", formatCode, result)

	return nil
}

func runExtract(cmd *cobra.Command, _ []string) error {
	pinblockHex, _ := cmd.Flags().GetString("pinblock")
	pan, _ := cmd.Flags().GetString("pan")
	formatCode, _ := cmd.Flags().GetString("format")

	result, err := pinblock.ExtractPinBlock(pinblockHex, pan, formatCode)
	if err != nil {
		return err
	}

	cmd.Printf("PIN extracted (format %s): %s\n", formatCode, result)

	return nil
}

func runFormats(cmd *cobra.Command, _ []string) error {
	pinblock.PrintSupportedFormats(cmd.OutOrStdout())
	return nil
}
