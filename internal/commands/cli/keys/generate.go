// Package keys provides key generation command implementation.
package keys

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/andrei-cloud/go_hsm/pkg/crypto"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
	"github.com/andrei-cloud/go_hsm/pkg/variantlmk"
	"github.com/spf13/cobra"
)

func newGenerateKeyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate a random cryptographic key",
		Long: `Generate a random cryptographic key of specified type and scheme.
The command outputs the key encrypted under LMK, its Key Check Value (KCV),
and key type description. Optionally displays the clear key for testing purposes.`,
		RunE: runGenerateKey,
	}

	// Add flags.
	cmd.Flags().String("type", "", "Key type code (e.g. 000, 001, 002)")
	cmd.Flags().String("scheme", "U", "Key scheme (X=single, U=double, T=triple length)")
	cmd.Flags().Bool("clear", false, "Display clear key value")
	cmd.Flags().Bool("pci", false, "Enable PCI compliance mode")

	if err := cmd.MarkFlagRequired("type"); err != nil {
		panic(err)
	}

	return cmd
}

func runGenerateKey(cmd *cobra.Command, _ []string) error {
	// Get command flags.
	keyType, _ := cmd.Flags().GetString("type")
	scheme, _ := cmd.Flags().GetString("scheme")
	showClear, _ := cmd.Flags().GetBool("clear")
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

	// Validate and normalize scheme.
	scheme = strings.ToUpper(scheme)
	if scheme != "X" && scheme != "U" && scheme != "T" {
		return fmt.Errorf("invalid scheme: %s (must be X, U, or T)", scheme)
	}

	schemeChar := scheme[0]

	// Determine key length based on scheme.
	var keyLen int
	switch schemeChar {
	case 'X':
		keyLen = 64 // Single length DES: 8 bytes = 64 bits.
	case 'U':
		keyLen = 128 // Double length DES: 16 bytes = 128 bits.
	case 'T':
		keyLen = 192 // Triple length DES: 24 bytes = 192 bits.
	default:
		return fmt.Errorf("unsupported scheme: %c", schemeChar)
	}

	// Generate random key.
	clearKeyHex, _, err := crypto.GenerateKey(keyLen, true)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Convert hex string to bytes.
	clearKey, err := hex.DecodeString(clearKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decode generated key: %w", err)
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
	cmd.Printf("Encrypted Key: %s%s\n", scheme, strings.ToUpper(hex.EncodeToString(encrypted)))
	cmd.Printf("KCV: %s\n", strings.ToUpper(hex.EncodeToString(kcv)))

	if showClear {
		cmd.Printf("Clear Key: %s\n", strings.ToUpper(hex.EncodeToString(clearKey)))
	}

	return nil
}
