// Package keys provides key import command implementation.
package keys

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
	"github.com/andrei-cloud/go_hsm/pkg/variantlmk"
	"github.com/spf13/cobra"
)

func newImportKeyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "import",
		Short: "Import a clear key under LMK",
		Long: `Import a clear key under Local Master Key (LMK) with validation.
The command performs key parity validation and outputs the encrypted key
under the specified LMK variant, its Key Check Value (KCV), and key type description.
If the key fails parity check, an error is returned unless force-parity is enabled,
which will fix the parity before importing.`,
		RunE: runImportKey,
	}

	// Add flags.
	cmd.Flags().String("key", "", "Clear key in hex format")
	cmd.Flags().String("type", "", "Key type code (e.g. 000, 001, 002)")
	cmd.Flags().String("scheme", "", "Key scheme (X=single, U=double, T=triple length)")
	cmd.Flags().Bool("force-parity", false, "Fix key parity if invalid")
	cmd.Flags().Bool("pci", false, "Enable PCI compliance mode")

	if err := cmd.MarkFlagRequired("key"); err != nil {
		panic(err)
	}
	if err := cmd.MarkFlagRequired("type"); err != nil {
		panic(err)
	}

	return cmd
}

func runImportKey(cmd *cobra.Command, _ []string) error {
	// Get command flags.
	keyHex, _ := cmd.Flags().GetString("key")
	keyType, _ := cmd.Flags().GetString("type")
	scheme, _ := cmd.Flags().GetString("scheme")
	forceParity, _ := cmd.Flags().GetBool("force-parity")
	pciMode, _ := cmd.Flags().GetBool("pci")

	// Load LMK set.
	lmkSet, err := variantlmk.LoadDefaultLMKSet()
	if err != nil {
		return fmt.Errorf("failed to load LMK set: %w", err)
	}

	// Validate key type.
	kt, err := variantlmk.GetKeyTypeDetails(keyType, pciMode)
	if err != nil {
		return fmt.Errorf("invalid key type: %w", err)
	}

	// Decode key from hex.
	clearKey, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("invalid key hex: %w", err)
	}

	// Validate key length and determine scheme if not provided.
	if scheme == "" {
		var expectedLen int
		switch len(clearKey) {
		case 8:
			scheme = "X"
			expectedLen = 8
		case 16:
			scheme = "U"
			expectedLen = 16
		case 24:
			scheme = "T"
			expectedLen = 24
		default:
			return fmt.Errorf("invalid key length: %d bytes (expected 8, 16, or 24)", len(clearKey))
		}
		cmd.Printf("Auto-detected scheme: %s (%d bytes)\n", scheme, expectedLen)
	} else {
		// Validate provided scheme.
		scheme = strings.ToUpper(scheme)
		var expectedLen int
		switch scheme {
		case "X":
			expectedLen = 8
		case "U":
			expectedLen = 16
		case "T":
			expectedLen = 24
		default:
			return fmt.Errorf("invalid scheme: %s (must be X, U, or T)", scheme)
		}

		if len(clearKey) != expectedLen {
			return fmt.Errorf("key length %d bytes does not match scheme %s (expected %d bytes)",
				len(clearKey), scheme, expectedLen)
		}
	}

	schemeChar := scheme[0]

	// Check and fix parity if needed.
	parityOK := cryptoutils.CheckKeyParity(clearKey)
	if !parityOK {
		if forceParity {
			cmd.Printf("Warning: Key has invalid parity, fixing...\n")
			clearKey = cryptoutils.FixKeyParity(clearKey)
		} else {
			return fmt.Errorf("key has invalid DES parity (use --force-parity to fix)")
		}
	}

	// Calculate KCV.
	kcv, err := cryptoutils.KeyCV(clearKey, 3)
	if err != nil {
		return fmt.Errorf("failed to calculate KCV: %w", err)
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
	cmd.Printf("Parity Check: %v\n", parityOK)
	cmd.Printf("Encrypted Key: %s%s\n", scheme, strings.ToUpper(hex.EncodeToString(encrypted)))
	cmd.Printf("KCV: %s\n", strings.ToUpper(hex.EncodeToString(kcv)))

	return nil
}
