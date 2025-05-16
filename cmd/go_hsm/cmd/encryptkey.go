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

var encryptKeyCmd = &cobra.Command{
	Use:   "encryptkey",
	Short: "Encrypt a clear key under variant LMK",
	Long: `Encrypt a clear key under variant LMK using specified key type.
The command performs key parity validation and outputs the encrypted key,
its Key Check Value (KCV) and key type description.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		// Get command flags
		clearKeyHex, _ := cmd.Flags().GetString("key")
		keyType, _ := cmd.Flags().GetString("type")
		scheme, _ := cmd.Flags().GetString("scheme")
		pciMode, _ := cmd.Flags().GetBool("pci")

		// Validate key scheme and length based on key length
		clearKey, err := hex.DecodeString(clearKeyHex)
		if err != nil {
			return fmt.Errorf("invalid key format: %w", err)
		}

		// Default to scheme X for single length if not specified.
		if scheme == "" {
			if len(clearKey) != 8 {
				return errors.New("scheme must be specified for double/triple length keys")
			}
			scheme = "X"
		}

		// Validate scheme based on key length
		switch len(clearKey) {
		case 8: // Single length
			if scheme != "X" && scheme != "" {
				return fmt.Errorf("invalid scheme for single length key: %s", scheme)
			}
			scheme = "X" // Normalize empty scheme to X
		case 16: // Double length
			if scheme != "U" {
				return fmt.Errorf("invalid scheme for double length key: want U, got %s", scheme)
			}
		case 24: // Triple length
			if scheme != "T" {
				return fmt.Errorf("invalid scheme for triple length key: want T, got %s", scheme)
			}
		default:
			return fmt.Errorf("invalid key length: %d bytes", len(clearKey))
		}

		// Validate key parity
		if !cryptoutils.CheckKeyParity(clearKey) {
			return errors.New("key parity check failed")
		}

		// Calculate KCV
		kcv := crypto.CalculateKCV(clearKey)

		// Set PCI mode
		variantlmk.SetPCIComplianceMode(pciMode)

		// Get key type details
		kt, err := variantlmk.GetKeyTypeDetails(keyType, pciMode)
		if err != nil {
			return fmt.Errorf("invalid key type: %w", err)
		}

		// Load LMK set
		lmkSet, err := variantlmk.LoadDefaultLMKSet()
		if err != nil {
			return fmt.Errorf("failed to load LMK set: %w", err)
		}

		// Encrypt under variant LMK
		encrypted, err := variantlmk.EncryptKeyUnderScheme(
			keyType,
			scheme[0],
			clearKey,
			lmkSet,
			false,
		)
		if err != nil {
			return fmt.Errorf("failed to encrypt key: %w", err)
		}

		// Output results
		cmd.Printf("Encrypted Key: %s\n", strings.ToUpper(hex.EncodeToString(encrypted)))
		cmd.Printf("KCV: %s\n", strings.ToUpper(hex.EncodeToString(kcv)))
		cmd.Printf("Key Type: %s\n", kt.String())
		cmd.Printf("Key Scheme: %c\n", scheme[0])

		return nil
	},
}

func init() {
	rootCmd.AddCommand(encryptKeyCmd)

	encryptKeyCmd.Flags().String("key", "", "Clear key in hex format")
	encryptKeyCmd.Flags().String("type", "", "Key type code (e.g. 009)")
	encryptKeyCmd.Flags().String("scheme", "U", "Key scheme (U=double length, T=triple length)")
	encryptKeyCmd.Flags().Bool("pci", false, "Enable PCI compliance mode")

	if err := encryptKeyCmd.MarkFlagRequired("key"); err != nil {
		panic(err)
	}
	if err := encryptKeyCmd.MarkFlagRequired("type"); err != nil {
		panic(err)
	}
}
