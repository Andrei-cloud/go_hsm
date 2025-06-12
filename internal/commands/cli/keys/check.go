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

	// Parse header (16 bytes).
	header := data[:16]
	offset := 16

	// Parse ASCII header fields.
	asciiLen := string(header[1:5])
	blockLen, err := strconv.Atoi(asciiLen)
	if err != nil {
		cmd.Printf("Error: invalid block length '%s'\n", asciiLen)
		return
	}

	usageCode := string(header[5:7])
	algorithm := header[7]
	modeOfUse := header[8]
	versionNum := string(header[9:11])
	exportability := header[11]
	optCountStr := string(header[12:14])
	optCount, err := strconv.Atoi(optCountStr)
	if err != nil {
		cmd.Printf("Error: invalid optional block count '%s'\n", optCountStr)
		return
	}

	reserved := string(header[14:16])

	// Validate total length.
	if len(data) != blockLen {
		cmd.Printf("Warning: actual key block length (%d) differs from declared length (%d)\n",
			len(data), blockLen)
	}

	// Display header as table.
	cmd.Println("Header (16 bytes)")
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "Offset\tField\tValue\tMeaning")
	fmt.Fprintf(w, "0\tVersion ID\t%c\t%s\n", header[0], getVersionMeaning(header[0]))
	fmt.Fprintf(w, "1-4\tKey Block length\t%s\tTotal length of key block: %d bytes\n",
		asciiLen, blockLen)
	fmt.Fprintf(w, "5-6\tKey usage\t%s\t%s\n", usageCode, getKeyUsageMeaning(usageCode))
	fmt.Fprintf(w, "7\tAlgorithm\t%c\t%s\n", algorithm, getAlgorithmMeaning(algorithm))
	fmt.Fprintf(w, "8\tMode of use\t%c\t%s\n", modeOfUse, getModeOfUseMeaning(modeOfUse))
	fmt.Fprintf(
		w,
		"9-10\tKey Version Number\t%s\t%s\n",
		versionNum,
		getKeyVersionMeaning(versionNum),
	)
	fmt.Fprintf(
		w,
		"11\tExportability\t%c\t%s\n",
		exportability,
		getExportabilityMeaning(exportability),
	)
	fmt.Fprintf(w, "12-13\tNumber of optional blocks\t%s\t%d optional blocks\n",
		optCountStr, optCount)
	fmt.Fprintf(w, "14-15\tLMK ID\t%s\t%s\n", reserved, getLMKIDMeaning(reserved))
	w.Flush()

	// Parse optional header blocks.
	totalOptionalLength := 0
	if optCount > 0 {
		cmd.Printf("\nOptional Header Blocks\n")

		for i := 0; i < optCount; i++ {
			if offset+4 > len(data) {
				cmd.Printf("Error: insufficient data for optional block %d header\n", i+1)
				return
			}

			// Parse optional block header.
			// Identifier: 2 ASCII bytes (e.g., "00", "PB", "KS", etc.).
			identifier := string(data[offset : offset+2])

			// Length: 2 hex-encoded ASCII bytes representing total block length.
			lengthStr := string(data[offset+2 : offset+4])

			// Convert hex-encoded length to integer.
			blockLength, err := strconv.ParseInt(lengthStr, 16, 32)
			if err != nil {
				cmd.Printf("Error: invalid optional block length '%s'\n", lengthStr)
				return
			}

			if offset+int(blockLength) > len(data) {
				cmd.Printf("Error: optional block %d extends beyond key block data\n", i+1)
				return
			}

			// Extract block data (excludes the 4-byte header).
			dataLength := int(blockLength) - 4
			var blockData []byte
			var dataStr string
			if dataLength > 0 {
				blockData = data[offset+4 : offset+4+dataLength]
				dataStr = string(blockData)
			}

			cmd.Printf("Optional Header %d\n", i+1)
			wOpt := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
			fmt.Fprintln(wOpt, "Field\tValue\tMeaning")
			fmt.Fprintf(
				wOpt,
				"Identifier\t%s\t%s\n",
				identifier,
				getOptionalBlockMeaning(identifier),
			)
			fmt.Fprintf(wOpt, "Length\t%s\t%d\n", lengthStr, blockLength)

			if dataLength > 0 {
				fmt.Fprintf(
					wOpt,
					"Data\t%s\t%s\n",
					dataStr,
					getOptionalBlockDataMeaning(identifier, dataStr),
				)
			} else {
				fmt.Fprintln(wOpt, "Data\t\t(no data)")
			}
			wOpt.Flush()

			offset += int(blockLength)
			totalOptionalLength += int(blockLength)
		}

		cmd.Printf("\nTotal Optional Header Length: %d bytes\n", totalOptionalLength)
	}

	// Calculate MAC length based on algorithm and format.
	var macLength int
	if scheme == 'S' || scheme == 'K' {
		// Thales format: 8 bytes for TDES, 8 bytes for AES (truncated CMAC).
		macLength = 8
	} else {
		// TR-31 format: 8 bytes for TDES, 16 bytes for AES.
		if algorithm == 'T' || algorithm == 'D' {
			macLength = 8
		} else {
			macLength = 16
		}
	}

	// Calculate encrypted key data length.
	if offset+macLength > len(data) {
		cmd.Printf("Error: insufficient data for MAC (need %d bytes)\n", macLength)
		return
	}

	encryptedKeyLength := len(data) - offset - macLength
	if encryptedKeyLength <= 0 {
		cmd.Println("Error: no encrypted key data present")
		return
	}

	// Extract encrypted key data and MAC.
	encryptedKey := data[offset : offset+encryptedKeyLength]
	mac := data[offset+encryptedKeyLength:]

	// Display encrypted key data.
	cmd.Printf("\nEncrypted Key Data (%d bytes)\n", encryptedKeyLength)

	var encryptedKeyHex string
	if scheme == 'S' || scheme == 'K' {
		// For Thales format, encrypted key data is already hex-encoded ASCII.
		encryptedKeyHex = strings.ToUpper(string(encryptedKey))
	} else {
		// For TR-31 format, convert binary data to hex.
		encryptedKeyHex = strings.ToUpper(hex.EncodeToString(encryptedKey))
	}

	// Display in rows of 32 hex characters (16 bytes per row).
	const bytesPerRow = 16
	for i := 0; i < len(encryptedKeyHex); i += bytesPerRow * 2 {
		end := i + bytesPerRow*2
		if end > len(encryptedKeyHex) {
			end = len(encryptedKeyHex)
		}
		cmd.Println(encryptedKeyHex[i:end])
	}

	// Display MAC.
	cmd.Printf("\nKey Block Authenticator (MAC)\n")
	if scheme == 'S' || scheme == 'K' {
		// For Thales format, MAC is already hex-encoded ASCII.
		cmd.Println(strings.ToUpper(string(mac)))
	} else {
		// For TR-31 format, convert binary MAC to hex.
		cmd.Println(strings.ToUpper(hex.EncodeToString(mac)))
	}

	// Summary.
	cmd.Printf("\nKey Block Summary:\n")
	cmd.Printf("- Format: %c (%s)\n", scheme, getKeyBlockFormatMeaning(scheme))
	cmd.Printf("- Total Length: %d bytes\n", len(data))
	cmd.Printf("- Header: 16 bytes\n")
	cmd.Printf("- Optional Headers: %d bytes (%d blocks)\n", totalOptionalLength, optCount)
	cmd.Printf("- Encrypted Key Data: %d bytes\n", encryptedKeyLength)
	cmd.Printf("- MAC: %d bytes\n", macLength)

	if lmkIndex >= 0 {
		cmd.Println("\nKey block validation is not yet implemented.")
	} else {
		cmd.Println("\nKey block parsed successfully. Provide --lmk-index to validate.")
	}
}
