// Package keys provides key management commands.
package keys

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/andrei-cloud/go_hsm/pkg/crypto"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
	"github.com/andrei-cloud/go_hsm/pkg/variantlmk"
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

func newCheckKeyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "check",
		Short: "Check and verify an encrypted key under LMK",
		Long: `Check and verify an encrypted key under Local Master Key (LMK).
The command decrypts the key, verifies its parity, calculates the Key Check Value (KCV),
and outputs detailed information about the key type and scheme.`,
		RunE: runCheckKey,
	}

	// Add flags.
	cmd.Flags().String("key", "", "Encrypted key with scheme prefix (e.g. U1234...)")
	cmd.Flags().String("type", "", "Key type code (e.g. 000, 001, 002)")
	cmd.Flags().String("scheme", "", "Key scheme override (X=single, U=double, T=triple length)")
	cmd.Flags().Bool("pci", false, "Enable PCI compliance mode")

	if err := cmd.MarkFlagRequired("key"); err != nil {
		panic(err)
	}
	if err := cmd.MarkFlagRequired("type"); err != nil {
		panic(err)
	}

	return cmd
}

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

	// Get all key type codes
	codes := make([]string, 0, len(keyTypes))
	for code := range keyTypes {
		codes = append(codes, code)
	}

	// Sort codes for consistent output
	sort.Strings(codes)

	// Create and configure tabwriter
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
	defer w.Flush()

	// Print header
	fmt.Fprintln(w, "Code\tName\tLMK Pair\tVariant")
	fmt.Fprintln(w, "----\t----\t--------\t-------")

	// Print key types in sorted order
	for _, code := range codes {
		kt := keyTypes[code]
		fmt.Fprintf(w, "%s\t%s\t%d\t%d\n",
			kt.Code,
			kt.Name,
			kt.LMKPair,
			kt.VariantID,
		)
	}

	return nil
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
		return errors.New("scheme must be X (single), U (double), or T (triple)")
	}

	schemeChar := byte(scheme[0])
	var keyLen int
	switch schemeChar {
	case 'X':
		keyLen = 64 // Single length (8 bytes = 64 bits)
	case 'U':
		keyLen = 128 // Double length (16 bytes = 128 bits)
	case 'T':
		keyLen = 192 // Triple length (24 bytes = 192 bits)
	}

	// Generate random key.
	clearKeyHex, _, err := crypto.GenerateKey(keyLen, true)
	if err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Decode hex key to bytes.
	clearKey, err := hex.DecodeString(clearKeyHex)
	if err != nil {
		return fmt.Errorf("failed to decode generated key: %w", err)
	}

	// Calculate KCV.
	kcv := crypto.CalculateKCV(clearKey)

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

func runImportKey(cmd *cobra.Command, _ []string) error {
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
			scheme = "X"
		case 16:
			scheme = "U"
		case 24:
			scheme = "T"
		default:
			return errors.New("invalid key length; must be 8, 16, or 24 bytes")
		}
	} else {
		scheme = strings.ToUpper(scheme)
		if scheme != "X" && scheme != "U" && scheme != "T" {
			return errors.New("scheme must be X (single), U (double), or T (triple)")
		}

		// Validate key length matches scheme.
		var expectedLen int
		switch scheme[0] {
		case 'X':
			expectedLen = 8 // Single length (8 bytes)
		case 'U':
			expectedLen = 16 // Double length (16 bytes)
		case 'T':
			expectedLen = 24 // Triple length (24 bytes)
		}
		if len(clearKey) != expectedLen {
			return fmt.Errorf("key length %d does not match scheme %s (expected %d bytes)",
				len(clearKey), scheme, expectedLen)
		}
	}

	// Check key parity.
	if !cryptoutils.CheckKeyParity(clearKey) {
		if forceParity {
			cryptoutils.FixKeyParity(clearKey)
		} else {
			return errors.New("key has invalid parity; use --force-parity to fix")
		}
	}

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

	schemeChar := byte(scheme[0])

	// Calculate KCV.
	kcv := crypto.CalculateKCV(clearKey)

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
}

func runCheckKey(cmd *cobra.Command, _ []string) error {
	// Get command flags.
	encryptedKeyHex, _ := cmd.Flags().GetString("key")
	keyType, _ := cmd.Flags().GetString("type")
	scheme, _ := cmd.Flags().GetString("scheme")
	pciMode, _ := cmd.Flags().GetBool("pci")

	// Validate encrypted key format.
	if len(encryptedKeyHex) < 2 {
		return errors.New("encrypted key must include scheme prefix")
	}

	// Extract scheme from key if not explicitly provided.
	keyScheme := byte(encryptedKeyHex[0])
	keyHex := encryptedKeyHex[1:]

	if scheme != "" {
		// Use explicitly provided scheme.
		scheme = strings.ToUpper(scheme)
		if scheme != "X" && scheme != "U" && scheme != "T" {
			return errors.New("scheme must be X (single), U (double), or T (triple)")
		}
		keyScheme = byte(scheme[0])
	}

	// Validate scheme character.
	if keyScheme != 'X' && keyScheme != 'U' && keyScheme != 'T' {
		return fmt.Errorf("invalid scheme character: %c", keyScheme)
	}

	// Decode encrypted key.
	encryptedKey, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("invalid encrypted key format: %w", err)
	}

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

	// Decrypt key under variant LMK.
	clearKey, err := variantlmk.DecryptKeyUnderScheme(
		keyType,
		keyScheme,
		encryptedKey,
		lmkSet,
		pciMode,
	)
	if err != nil {
		return fmt.Errorf("failed to decrypt key: %w", err)
	}

	// Verify key parity.
	parityValid := cryptoutils.CheckKeyParity(clearKey)

	// Calculate KCV.
	kcv := crypto.CalculateKCV(clearKey)

	// Output results.
	cmd.Printf("Key Type: %s\n", kt.String())
	cmd.Printf("Key Scheme: %c\n", keyScheme)
	cmd.Printf("Encrypted Key: %s\n", encryptedKeyHex)
	cmd.Printf("KCV: %s\n", strings.ToUpper(hex.EncodeToString(kcv)))
	cmd.Printf("Parity Valid: %t\n", parityValid)

	return nil
}
