package cmd

import (
	"errors"

	"github.com/andrei-cloud/go_hsm/internal/cli"
	"github.com/spf13/cobra"
)

var pinblockCmd = &cobra.Command{
	Use:   "pinblock",
	Short: "Generate PIN block in specified format or extract PIN from PIN block",
	Long: `Generate PIN block using specified PIN, PAN, and Thales format code.
Supported formats can be listed using the --list-formats flag.
Alternatively, extract the clear PIN from a PIN block using the --extract flag.`,
	Example: `  # Generate ISO Format 0 PIN block
  go_hsm pinblock --pin 1234 --pan 4111111111111111 --format 01

  # Extract PIN from PIN block
  go_hsm pinblock --extract --pinblock 123456789ABCDEF --pan 4111111111111111 --format 01

  # List supported formats
  go_hsm pinblock --list-formats`,
	SilenceErrors: true,
	SilenceUsage:  true,
	RunE: func(cmd *cobra.Command, _ []string) error {
		pin, _ := cmd.Flags().GetString("pin")
		pan, _ := cmd.Flags().GetString("pan")
		formatCode, _ := cmd.Flags().GetString("format")
		listFormats, _ := cmd.Flags().GetBool("list-formats")
		extract, _ := cmd.Flags().GetBool("extract")
		pinblockHex, _ := cmd.Flags().GetString("pinblock")

		if listFormats {
			cli.PrintSupportedFormats(cmd.OutOrStdout())
			return nil
		}

		if extract {
			if pinblockHex == "" || pan == "" || formatCode == "" {
				return errors.New("pinblock, pan, and format are required")
			}
			result, err := cli.ExtractPinBlock(pinblockHex, pan, formatCode)
			if err != nil {
				return err
			}
			cmd.Printf("pin extracted (format %s): %s\n", formatCode, result)
			return nil
		}

		if pin == "" || pan == "" || formatCode == "" {
			return errors.New("pin, pan, and format are required")
		}

		result, err := cli.GeneratePinBlock(pin, pan, formatCode)
		if err != nil {
			return err
		}

		cmd.Printf("pin block generated (format %s): %s\n", formatCode, result)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(pinblockCmd)

	pinblockCmd.Flags().String("pin", "", "PIN number (4-12 digits)")
	pinblockCmd.Flags().String("pan", "", "Primary Account Number (card number)")
	pinblockCmd.Flags().
		String("format", "", "Thales format code (e.g., 01 for ISO 0)")
	pinblockCmd.Flags().
		Bool("list-formats", false, "List supported PIN block formats")
	pinblockCmd.Flags().Bool("extract", false, "Extract clear PIN from PIN block")
	pinblockCmd.Flags().
		String("pinblock", "", "PIN block hex string to extract PIN from")
}
