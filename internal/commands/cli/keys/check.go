// Package keys provides key check command implementation.
package keys

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/andrei-cloud/go_hsm/internal/hsm/logic"
	"github.com/andrei-cloud/go_hsm/pkg/crypto"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
	"github.com/andrei-cloud/go_hsm/pkg/variantlmk"
	"github.com/spf13/cobra"
)

func newCheckKeyCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:  "check",
		RunE: runCheckKey,
	}

	// Add flags.
	cmd.Flags().String("key", "", "Encrypted key with scheme prefix (e.g. U1234...)")
	cmd.Flags().String("type", "", "Key type code (e.g. 000, 001, 002)")
	cmd.Flags().String("scheme", "", "Key scheme override (X=single, U=double, T=triple length)")
	cmd.Flags().Bool("pci", false, "Enable PCI compliance mode")
	cmd.Flags().String("keyblock", "", "Key block string to parse.")
	cmd.Flags().String("lmk-id", "00", "LMK ID for key validation (00=variant, 01=key block)")

	return cmd
}

func runCheckKey(cmd *cobra.Command, _ []string) error {
	// Read LMK ID flag
	lmkID, _ := cmd.Flags().GetString("lmk-id")

	// Key block mode
	keyBlock, _ := cmd.Flags().GetString("keyblock")
	if keyBlock != "" {
		runCheckKeyBlock(cmd, keyBlock)
		return nil
	}

	// Variant key mode: decrypt via registry
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

	// Validate key type.
	kt, err := variantlmk.GetKeyTypeDetails(keyType, pciMode)
	if err != nil {
		return fmt.Errorf("invalid key type: %w", err)
	}

	// Lookup LMK engine for variant.
	engine, ok := logic.LMKRegistry[lmkID]
	if !ok || engine.GetLMKType() != logic.LMKTypeVariant {
		return fmt.Errorf("invalid or unsupported LMK ID '%s' for variant key", lmkID)
	}

	// Decrypt using registry engine.
	clearKey, err := engine.DecryptUnderLMK(encryptedKey, keyType, keyScheme, lmkID)
	if err != nil {
		return fmt.Errorf("failed to decrypt key under LMK %s: %w", lmkID, err)
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

// runCheckKeyBlock parses and validates a key block using registry LMK.
func runCheckKeyBlock(cmd *cobra.Command, keyBlock string) {
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
	var blockLen int
	var err error

	// Try parsing as decimal first, then as hex if that fails.
	blockLen, err = strconv.Atoi(asciiLen)
	if err != nil {
		// If decimal parsing fails, try hex parsing.
		blockLenInt64, hexErr := strconv.ParseInt(asciiLen, 16, 32)
		if hexErr != nil {
			cmd.Printf("Error: invalid block length '%s' (not decimal or hex)\n", asciiLen)
			return
		}
		blockLen = int(blockLenInt64)
		cmd.Printf(
			"Info: interpreted length field '%s' as hexadecimal (%d decimal)\n",
			asciiLen,
			blockLen,
		)
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
	_, _ = fmt.Fprintln(w, "Offset\tField\tValue\tMeaning")
	_, _ = fmt.Fprintf(w, "0\tVersion ID\t%c\t%s\n", header[0], getVersionMeaning(header[0]))
	_, _ = fmt.Fprintf(w, "1-4\tKey Block length\t%s\tTotal length of key block: %d bytes\n",
		asciiLen, blockLen)
	_, _ = fmt.Fprintf(w, "5-6\tKey usage\t%s\t%s\n", usageCode, getKeyUsageMeaning(usageCode))
	_, _ = fmt.Fprintf(w, "7\tAlgorithm\t%c\t%s\n", algorithm, getAlgorithmMeaning(algorithm))
	_, _ = fmt.Fprintf(w, "8\tMode of use\t%c\t%s\n", modeOfUse, getModeOfUseMeaning(modeOfUse))
	_, _ = fmt.Fprintf(
		w,
		"9-10\tKey Version Number\t%s\t%s\n",
		versionNum,
		getKeyVersionMeaning(versionNum),
	)
	_, _ = fmt.Fprintf(
		w,
		"11\tExportability\t%c\t%s\n",
		exportability,
		getExportabilityMeaning(exportability),
	)
	_, _ = fmt.Fprintf(w, "12-13\tNumber of optional blocks\t%s\t%d optional blocks\n",
		optCountStr, optCount)
	_, _ = fmt.Fprintf(w, "14-15\tLMK ID\t%s\t%s\n", reserved, getLMKIDMeaning(reserved))
	_ = w.Flush()

	// Parse optional header blocks.
	totalOptionalLength := 0
	if optCount > 0 {
		cmd.Printf("\nOptional Header Blocks\n")

		for i := range optCount {
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
			_, _ = fmt.Fprintln(wOpt, "Field\tValue\tMeaning")
			_, _ = fmt.Fprintf(
				wOpt,
				"Identifier\t%s\t%s\n",
				identifier,
				getOptionalBlockMeaning(identifier),
			)
			_, _ = fmt.Fprintf(wOpt, "Length\t%s\t%d\n", lengthStr, blockLength)

			if dataLength > 0 {
				_, _ = fmt.Fprintf(
					wOpt,
					"Data\t%s\t%s\n",
					dataStr,
					getOptionalBlockDataMeaning(identifier, dataStr),
				)
			} else {
				_, _ = fmt.Fprintln(wOpt, "Data\t\t(no data)")
			}
			_ = wOpt.Flush()

			offset += int(blockLength)
			totalOptionalLength += int(blockLength)
		}

		cmd.Printf("\nTotal Optional Header Length: %d bytes\n", totalOptionalLength)
	} // For Thales 'S' format, the remaining data after header and optional blocks is hex-encoded.
	macStartIdx := offset
	hexEncodedData := data[macStartIdx:]

	// Determine MAC length by format for hex-encoded data.
	macLengthHex := 16 // Default for TR-31 'R' format (16 hex chars = 8 bytes)
	if scheme == 'S' || scheme == 'K' {
		// For Thales format, try to determine MAC length based on remaining data
		// We need an even number of hex characters total
		if len(hexEncodedData)%2 != 0 {
			cmd.Printf(
				"Warning: hex-encoded data has odd length (%d chars), key block may be malformed\n",
				len(hexEncodedData),
			) // Try to make it work by assuming a smaller MAC
			if len(hexEncodedData) < 5 {
				cmd.Printf("Error: insufficient hex data length for any reasonable MAC size\n")
				return
			}
			macLengthHex = 4 // 4 hex chars = 2 bytes MAC (very short)
		} else {
			// Even length - use standard MAC sizes
			if len(hexEncodedData) <= 32 {
				macLengthHex = 8 // 8 hex chars = 4 bytes MAC
			} else {
				macLengthHex = 16 // 16 hex chars = 8 bytes MAC (standard)
			}
		}
	}

	// Calculate encrypted key data length in hex chars.
	if len(hexEncodedData) < macLengthHex {
		cmd.Printf(
			"Error: insufficient hex data for MAC (need %d hex chars, have %d)\n",
			macLengthHex,
			len(hexEncodedData),
		)

		return
	}

	encryptedKeyLengthHex := len(hexEncodedData) - macLengthHex
	if encryptedKeyLengthHex <= 0 {
		cmd.Println("Error: no encrypted key data present")
		return
	}

	// Extract encrypted key data and MAC from hex-encoded data.
	encryptedKeyHex := string(hexEncodedData[:encryptedKeyLengthHex])
	macHex := string(hexEncodedData[encryptedKeyLengthHex:])

	// Display encrypted key data.
	encryptedKeyBytes := encryptedKeyLengthHex / 2 // Convert hex chars to bytes
	cmd.Printf("\nEncrypted Key Data (%d bytes)\n", encryptedKeyBytes)

	// Display in rows of 32 hex characters (16 bytes per row).
	const bytesPerRow = 16
	encryptedKeyDisplay := strings.ToUpper(encryptedKeyHex)
	for i := 0; i < len(encryptedKeyDisplay); i += bytesPerRow * 2 {
		end := i + bytesPerRow*2
		if end > len(encryptedKeyDisplay) {
			end = len(encryptedKeyDisplay)
		}
		cmd.Println(encryptedKeyDisplay[i:end])
	}

	// Display MAC.
	cmd.Printf("\nKey Block Authenticator (MAC)\n")
	cmd.Println(strings.ToUpper(macHex))

	// Summary.
	macBytes := macLengthHex / 2 // Convert hex chars to bytes
	cmd.Printf("\nKey Block Summary:\n")
	cmd.Printf("- Format: %c (%s)\n", scheme, getKeyBlockFormatMeaning(scheme))
	cmd.Printf("- Total Length: %d bytes\n", len(data))
	cmd.Printf("- Header: 16 bytes\n")
	cmd.Printf("- Optional Headers: %d bytes (%d blocks)\n", totalOptionalLength, optCount)
	cmd.Printf("- Encrypted Key Data: %d bytes\n", encryptedKeyBytes)
	cmd.Printf("- MAC: %d bytes\n", macBytes)

	// Determine key-block LMK ID
	lmkID, _ := cmd.Flags().GetString("lmk-id")
	if lmkID == "00" {
		lmkID = "01"
	}

	engine, ok := logic.LMKRegistry[lmkID]
	if !ok || engine.GetLMKType() != logic.LMKTypeKeyBlock {
		cmd.Printf("Error: invalid LMK ID '%s' for key block\n", lmkID)
		return
	}

	// Decrypt key block
	clearKey, err := engine.DecryptUnderLMK([]byte(keyBlock), "", scheme, lmkID)
	if err != nil {
		if strings.Contains(err.Error(), "mac verification failed") {
			cmd.Printf("Key block validation failed: %v\n", err)
			return
		}
		cmd.Printf("Key block validation failed: %v\n", err)

		return
	}

	cmd.Println("Key block validated.")
	cmd.Printf("Clear Key: %X\n", clearKey)
}
