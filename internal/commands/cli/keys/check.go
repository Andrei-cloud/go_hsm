// Package keys provides key check command implementation.
package keys

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/andrei-cloud/go_hsm/pkg/crypto"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
	"github.com/andrei-cloud/go_hsm/pkg/variantlmk"
	"github.com/spf13/cobra"
)

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
	cmd.Flags().String("keyblock", "", "Key block string to parse.")
	cmd.Flags().Int("lmk-index", -1, "LMK index for key block validation (optional).")

	return cmd
}

func runCheckKey(cmd *cobra.Command, _ []string) error {
	// New flags for key block parsing.
	keyBlock, _ := cmd.Flags().GetString("keyblock")
	lmkIndex, _ := cmd.Flags().GetInt("lmk-index")
	if keyBlock != "" {
		runCheckKeyBlock(cmd, keyBlock, lmkIndex)

		return nil
	}

	// Ensure required flags when not using keyblock.
	encryptedKeyHex, _ := cmd.Flags().GetString("key")
	keyType, _ := cmd.Flags().GetString("type")
	schemeStr, _ := cmd.Flags().GetString("scheme")
	pciMode, _ := cmd.Flags().GetBool("pci")
	if encryptedKeyHex == "" {
		return errors.New("--key is required when not parsing a key block")
	}
	if keyType == "" {
		return errors.New("--type is required when not parsing a key block")
	}

	// Validate encrypted key format.
	if len(encryptedKeyHex) < 2 {
		return errors.New("encrypted key must include scheme prefix")
	}

	// Extract scheme from key if not explicitly provided.
	keyScheme := encryptedKeyHex[0]
	keyHex := encryptedKeyHex[1:]
	// Determine scheme to use for validation and output.
	persistScheme := string(keyScheme)

	// Override scheme if provided.
	if schemeStr != "" {
		schemeStr = strings.ToUpper(schemeStr)
		if schemeStr != "X" && schemeStr != "U" && schemeStr != "T" {
			return errors.New("scheme must be X (single), U (double), or T (triple)")
		}
		keyScheme = schemeStr[0]
		persistScheme = schemeStr
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
	cmd.Printf(
		"Encrypted Key: %s%s\n",
		persistScheme,
		strings.ToUpper(hex.EncodeToString(encryptedKey)),
	)
	cmd.Printf("KCV: %s\n", strings.ToUpper(hex.EncodeToString(kcv)))
	cmd.Printf("Parity Valid: %t\n", parityValid)

	return nil
}

// runCheckKeyBlock parses and optionally validates a Thales or TR-31 key block.
func runCheckKeyBlock(cmd *cobra.Command, keyBlock string, lmkIndex int) {
	if len(keyBlock) < 1 {
		cmd.Println("Error: key block is empty.")
		return
	}
	scheme := keyBlock[0]
	if scheme != 'S' && scheme != 'K' && scheme != 'R' {
		cmd.Println("Error: key block must start with S, K, or R prefix.")
		return
	}
	data := []byte(keyBlock[1:]) // skip scheme prefix

	if len(data) < 16 {
		cmd.Println("Error: key block too short (minimum 16 bytes for header).")
		return
	}
	header := data[:16]

	// Parse ASCII header fields.
	asciiLen := string(header[1:5])
	blockLen, err := strconv.Atoi(asciiLen)
	if err != nil {
		blockLen = 0
	}
	usageCode := string(header[5:7])
	versionNum := string(header[9:11])
	optCountStr := string(header[12:14])
	optCount, err := strconv.Atoi(optCountStr)
	if err != nil {
		optCount = 0
	}
	lmkIDStr := string(header[14:16])
	lmkID, err := strconv.Atoi(lmkIDStr)
	if err != nil {
		lmkID = -1
	}

	// Display header as table.
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Offset\tField\tValue\tMeaning")
	fmt.Fprintf(w, "0\tVersion ID\t%c\t%s\n", header[0], getVersionMeaning(header[0]))
	fmt.Fprintf(
		w,
		"1-4\tKey Block length\t%s\tTotal length of key block: %d bytes.\n",
		asciiLen,
		blockLen,
	)
	fmt.Fprintf(w, "5-6\tKey usage\t%s\t%s\n", usageCode, getKeyUsageMeaning(usageCode))
	fmt.Fprintf(w, "7\tAlgorithm\t%c\t%s\n", header[7], getAlgorithmMeaning(header[7]))
	fmt.Fprintf(w, "8\tMode of use\t%c\t%s\n", header[8], getModeOfUseMeaning(header[8]))
	fmt.Fprintf(
		w,
		"9-10\tKey Version Number\t%s\t%s\n",
		versionNum,
		getKeyVersionMeaning(versionNum),
	)
	fmt.Fprintf(w, "11\tExportability\t%c\t%s\n", header[11], getExportabilityMeaning(header[11]))
	fmt.Fprintf(
		w,
		"12-13\tNumber of optional blocks\t%s\t%d optional blocks.\n",
		optCountStr,
		optCount,
	)
	fmt.Fprintf(w, "14-15\tLMK ID\t%s\tLMK identifier: %d.\n", lmkIDStr, lmkID)
	w.Flush()

	if lmkIndex >= 0 {
		cmd.Println("\nKey block validation is not yet implemented.")
	} else {
		cmd.Println("\nKey block parsed successfully. Provide --lmk-index to validate.")
	}
}
