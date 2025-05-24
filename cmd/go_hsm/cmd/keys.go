package cmd

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/andrei-cloud/go_hsm/pkg/crypto"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
	"github.com/andrei-cloud/go_hsm/pkg/variantlmk"
	"github.com/spf13/cobra"
)

// keysCmd represents the main keys command.
var keysCmd = &cobra.Command{
	Use:   "keys",
	Short: "Key generation and import operations",
	Long: `Key generation and import operations for the HSM.
This command provides subcommands for generating random keys and importing clear keys
under Local Master Keys (LMK) with proper validation and parity checking.`,
}

// generateKeyCmd represents the key generation subcommand.
var generateKeyCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a random cryptographic key",
	Long: `Generate a random cryptographic key of specified type and scheme.
The command outputs the key encrypted under LMK, its Key Check Value (KCV),
and key type description. If the clear flag is enabled, the clear key value
is also displayed.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		// Get command flags.
		keyType, _ := cmd.Flags().GetString("type")
		scheme, _ := cmd.Flags().GetString("scheme")
		showClear, _ := cmd.Flags().GetBool("clear")
		pciMode, _ := cmd.Flags().GetBool("pci")

		// Validate key type.
		variantlmk.SetPCIComplianceMode(pciMode)
		kt, err := variantlmk.GetKeyTypeDetails(keyType, pciMode)
		if err != nil {
			return fmt.Errorf("invalid key type: %w", err)
		}

		// Validate and normalize scheme.
		if scheme == "" {
			scheme = "U" // Default to double length
		}
		scheme = strings.ToUpper(scheme)
		if len(scheme) != 1 {
			return errors.New("scheme must be a single character")
		}
		schemeChar := scheme[0]

		// Validate scheme.
		if schemeChar != 'X' && schemeChar != 'U' && schemeChar != 'T' {
			return fmt.Errorf("invalid scheme: %c (valid: X, U, T)", schemeChar)
		}

		// Determine key length based on scheme.
		var keyLength int
		switch schemeChar {
		case 'X':
			keyLength = 8 // Single length
		case 'U':
			keyLength = 16 // Double length
		case 'T':
			keyLength = 24 // Triple length
		}

		// Generate random key.
		clearKey, err := cryptoutils.GenerateRandomKey(keyLength)
		if err != nil {
			return fmt.Errorf("failed to generate random key: %w", err)
		}

		// Calculate KCV.
		kcv := crypto.CalculateKCV(clearKey)

		// Load LMK set.
		lmkSet, err := variantlmk.LoadDefaultLMKSet()
		if err != nil {
			return fmt.Errorf("failed to load LMK set: %w", err)
		}

		// Encrypt under variant LMK.
		encrypted, err := variantlmk.EncryptKeyUnderScheme(
			keyType,
			schemeChar,
			clearKey,
			lmkSet,
			false,
		)
		if err != nil {
			return fmt.Errorf("failed to encrypt key: %w", err)
		}

		// Output results.
		cmd.Printf("Key Type: %s\n", kt.String())
		cmd.Printf("Key Scheme: %c\n", schemeChar)
		cmd.Printf("Encrypted Key: %s%s\n", scheme, strings.ToUpper(hex.EncodeToString(encrypted)))
		cmd.Printf("KCV: %s\n", strings.ToUpper(hex.EncodeToString(kcv)))

		if showClear {
			cmd.Printf("Clear Key: %s\n", strings.ToUpper(hex.EncodeToString(clearKey)))
		}

		return nil
	},
}

// importKeyCmd represents the key import subcommand.
var importKeyCmd = &cobra.Command{
	Use:   "import",
	Short: "Import a clear key under LMK",
	Long: `Import a clear key under Local Master Key (LMK) with validation.
The command performs key parity validation and outputs the encrypted key
under the specified LMK variant, its Key Check Value (KCV), and key type description.
If the key fails parity check, an error is returned unless force-parity is enabled,
which will fix the parity before importing.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		// Get command flags.
		clearKeyHex, _ := cmd.Flags().GetString("key")
		keyType, _ := cmd.Flags().GetString("type")
		scheme, _ := cmd.Flags().GetString("scheme")
		forceParity, _ := cmd.Flags().GetBool("force-parity")
		pciMode, _ := cmd.Flags().GetBool("pci")

		// Validate key format.
		clearKey, err := hex.DecodeString(clearKeyHex)
		if err != nil {
			return fmt.Errorf("invalid key format: %w", err)
		}

		// Validate and normalize scheme based on key length.
		if scheme == "" {
			switch len(clearKey) {
			case 8:
				scheme = "X" // Single length
			case 16:
				scheme = "U" // Double length
			case 24:
				scheme = "T" // Triple length
			default:
				return fmt.Errorf("invalid key length: %d bytes", len(clearKey))
			}
		}

		scheme = strings.ToUpper(scheme)
		if len(scheme) != 1 {
			return errors.New("scheme must be a single character")
		}
		schemeChar := scheme[0]

		// Validate scheme based on key length.
		switch len(clearKey) {
		case 8: // Single length
			if schemeChar != 'X' {
				return fmt.Errorf(
					"invalid scheme for single length key: %c (expected: X)",
					schemeChar,
				)
			}
		case 16: // Double length
			if schemeChar != 'U' {
				return fmt.Errorf(
					"invalid scheme for double length key: %c (expected: U)",
					schemeChar,
				)
			}
		case 24: // Triple length
			if schemeChar != 'T' {
				return fmt.Errorf(
					"invalid scheme for triple length key: %c (expected: T)",
					schemeChar,
				)
			}
		default:
			return fmt.Errorf("invalid key length: %d bytes", len(clearKey))
		}

		// Check key parity.
		if !cryptoutils.CheckKeyParity(clearKey) {
			if forceParity {
				clearKey = cryptoutils.FixKeyParity(clearKey)
				cmd.Printf("Warning: Key parity was invalid and has been fixed\n")
			} else {
				return errors.New("key parity check failed")
			}
		}

		// Validate key type.
		variantlmk.SetPCIComplianceMode(pciMode)
		kt, err := variantlmk.GetKeyTypeDetails(keyType, pciMode)
		if err != nil {
			return fmt.Errorf("invalid key type: %w", err)
		}

		// Calculate KCV.
		kcv := crypto.CalculateKCV(clearKey)

		// Load LMK set.
		lmkSet, err := variantlmk.LoadDefaultLMKSet()
		if err != nil {
			return fmt.Errorf("failed to load LMK set: %w", err)
		}

		// Encrypt under variant LMK.
		encrypted, err := variantlmk.EncryptKeyUnderScheme(
			keyType,
			schemeChar,
			clearKey,
			lmkSet,
			false,
		)
		if err != nil {
			return fmt.Errorf("failed to encrypt key: %w", err)
		}

		// Output results.
		cmd.Printf("Key Type: %s\n", kt.String())
		cmd.Printf("Key Scheme: %c\n", schemeChar)
		cmd.Printf("Encrypted Key: %s%s\n", scheme, strings.ToUpper(hex.EncodeToString(encrypted)))
		cmd.Printf("KCV: %s\n", strings.ToUpper(hex.EncodeToString(kcv)))

		return nil
	},
}

func init() {
	// Add keys command to root.
	rootCmd.AddCommand(keysCmd)

	// Add subcommands to keys command.
	keysCmd.AddCommand(generateKeyCmd)
	keysCmd.AddCommand(importKeyCmd)

	// Generate key command flags.
	generateKeyCmd.Flags().String("type", "", "Key type code (e.g. 000, 001, 002)")
	generateKeyCmd.Flags().String("scheme", "U", "Key scheme (X=single, U=double, T=triple length)")
	generateKeyCmd.Flags().Bool("clear", false, "Display clear key value")
	generateKeyCmd.Flags().Bool("pci", false, "Enable PCI compliance mode")

	if err := generateKeyCmd.MarkFlagRequired("type"); err != nil {
		panic(err)
	}

	// Import key command flags.
	importKeyCmd.Flags().String("key", "", "Clear key in hex format")
	importKeyCmd.Flags().String("type", "", "Key type code (e.g. 000, 001, 002)")
	importKeyCmd.Flags().String("scheme", "", "Key scheme (X=single, U=double, T=triple length)")
	importKeyCmd.Flags().Bool("force-parity", false, "Fix key parity if invalid")
	importKeyCmd.Flags().Bool("pci", false, "Enable PCI compliance mode")

	if err := importKeyCmd.MarkFlagRequired("key"); err != nil {
		panic(err)
	}
	if err := importKeyCmd.MarkFlagRequired("type"); err != nil {
		panic(err)
	}
}
