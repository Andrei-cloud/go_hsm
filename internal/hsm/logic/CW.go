// Package logic implements HSM command business logic.
package logic

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/internal/logging" // Added import.
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteCW executes the CW command to generate a CVV.
func ExecuteCW(input []byte) ([]byte, error) {
	logDebug(
		fmt.Sprintf("ExecuteCW input: %s", logging.FormatData(input)),
	)

	var cvkHexStr string
	var panStartIndex int
	var clearCVK []byte // This will hold the CVK after potential decryption.

	// Minimum data length after key part: PAN_hex (min 1) + ';' (1) + expDate (4) + servCode (3) = 9 bytes.
	const minDataLengthAfterKey = 1 + 1 + 4 + 3

	if len(input) > 0 && input[0] == 'U' {
		// Case 1: 'U' prefixed - means an ENCRYPTED DOUBLE-LENGTH CVK is provided.
		// Format: U<32H_encrypted_CVK> + PAN_data...
		logDebug("CVK is U-prefixed: expecting encrypted double-length CVK.")
		// Min length: 1('U') + 32(EncCVK_hex) + minDataLengthAfterKey
		if len(input) < 1+32+minDataLengthAfterKey {
			logDebug("Error: Not enough data for U-prefixed encrypted double-length CVK.")
			return nil, errorcodes.Err15 // Not enough data.
		}
		cvkHexStr = string(input[1 : 1+32])
		panStartIndex = 1 + 32
		logDebug(fmt.Sprintf("Encrypted double-length CVK hex (U-prefixed): %s", cvkHexStr))

		encryptedCVKBytes, err := hex.DecodeString(cvkHexStr)
		if err != nil {
			logDebug(fmt.Sprintf("Error decoding U-prefixed encrypted CVK hex: %v", err))
			return nil, errorcodes.Err15 // Invalid CVK format.
		}

		logDebug("Decrypting U-prefixed double-length CVK using type '402' scheme 'U'...")
		// Key Type "402" for CVK, Scheme 'U' for double-length key.
		decryptedCVK, err := decryptUnderLMK(encryptedCVKBytes, "402", 'U')
		if err != nil {
			logDebug(fmt.Sprintf("Error decrypting U-prefixed CVK: %v", err))
			if hsmErr, ok := err.(errorcodes.HSMError); ok {
				return nil, hsmErr
			}
			return nil, errorcodes.Err10 // Decryption failure.
		}
		clearCVK = decryptedCVK
		logDebug(
			fmt.Sprintf("Decrypted CVK from U-prefixed input: %s", logging.FormatData(clearCVK)),
		)
	} else {
		// Case 2: Not 'U' prefixed - means a PAIR OF ENCRYPTED SINGLE-LENGTH CVKs is PROVIDED.
		// Format: <16H_encrypted_CVKA><16H_encrypted_CVKB> + PAN_data...
		logDebug("CVK is not U-prefixed: expecting a pair of encrypted single-length CVKs.")
		// Min length: 16(EncCVKA_hex) + 16(EncCVKB_hex) + minDataLengthAfterKey
		if len(input) < 16+16+minDataLengthAfterKey {
			logDebug("Error: Not enough data for encrypted CVK pair.")
			return nil, errorcodes.Err15 // Not enough data.
		}

		cvkaHexStr := string(input[0:16])
		cvkbHexStr := string(input[16:32])
		panStartIndex = 32 // Data starts after the 32 hex chars of the key pair.

		logDebug(fmt.Sprintf("Encrypted CVKA hex: %s", cvkaHexStr))
		logDebug(fmt.Sprintf("Encrypted CVKB hex: %s", cvkbHexStr))

		encryptedCVKABytes, err := hex.DecodeString(cvkaHexStr)
		if err != nil {
			logDebug(fmt.Sprintf("Error decoding encrypted CVKA hex: %v", err))
			return nil, errorcodes.Err15 // Invalid CVK format.
		}

		encryptedCVKBBytes, err := hex.DecodeString(cvkbHexStr)
		if err != nil {
			logDebug(fmt.Sprintf("Error decoding encrypted CVKB hex: %v", err))
			return nil, errorcodes.Err15 // Invalid CVK format.
		}

		logDebug("Decrypting CVKA using type '402' scheme 'X'...")
		// Key Type "402" for CVK, Scheme 'X' for single-length key.
		decryptedCVKA, err := decryptUnderLMK(encryptedCVKABytes, "402", 'X')
		if err != nil {
			logDebug(fmt.Sprintf("Error decrypting CVKA: %v", err))
			if hsmErr, ok := err.(errorcodes.HSMError); ok {
				return nil, hsmErr
			}
			return nil, errorcodes.Err10 // Decryption failure.
		}
		if !cryptoutils.CheckKeyParity(decryptedCVKA) {
			logDebug("Error: Decrypted CVKA parity check failed.")
			return nil, errorcodes.Err10 // CVK A or CVK B parity error.
		}
		logDebug(fmt.Sprintf("Decrypted CVKA: %s", logging.FormatData(decryptedCVKA)))
		if len(decryptedCVKA) != 8 {
			logDebug(fmt.Sprintf("Error: Decrypted CVKA is not single length (8 bytes). Length: %d", len(decryptedCVKA)))
			return nil, errorcodes.Err10 // Key component length error.
		}

		logDebug("Decrypting CVKB using type '402' scheme 'X'...")
		decryptedCVKB, err := decryptUnderLMK(encryptedCVKBBytes, "402", 'X')
		if err != nil {
			logDebug(fmt.Sprintf("Error decrypting CVKB: %v", err))
			if hsmErr, ok := err.(errorcodes.HSMError); ok {
				return nil, hsmErr
			}
			return nil, errorcodes.Err10 // Decryption failure.
		}
		if !cryptoutils.CheckKeyParity(decryptedCVKB) {
			logDebug("Error: Decrypted CVKB parity check failed.")
			return nil, errorcodes.Err10 // CVK A or CVK B parity error.
		}
		logDebug(fmt.Sprintf("Decrypted CVKB: %s", logging.FormatData(decryptedCVKB)))
		if len(decryptedCVKB) != 8 {
			logDebug(fmt.Sprintf("Error: Decrypted CVKB is not single length (8 bytes). Length: %d", len(decryptedCVKB)))
			return nil, errorcodes.Err10 // Key component length error.
		}

		clearCVK = append(decryptedCVKA, decryptedCVKB...)
		logDebug(fmt.Sprintf("Combined clear CVK from pair: %s", logging.FormatData(clearCVK)))
	}

	logDebug(
		fmt.Sprintf("Clear CVK for validation: %s", logging.FormatData(clearCVK)),
	) // Replaced hex.EncodeToString with logging.FormatData.
	logDebug("Validating clear CVK length and parity.")
	// Validate the clear CVK (length and parity).

	// CVK for Visa CVV must be 16 bytes (double-length DES key).
	if len(clearCVK) != 16 { // Double-length key.
		logDebug(fmt.Sprintf("Error: CVK length is %d, expected 16.", len(clearCVK)))
		return nil, errorcodes.Err27 // CVK not double length.
	}

	if !cryptoutils.CheckKeyParity(clearCVK) {
		logDebug("Error: CVK parity check failed.")
		return nil, errorcodes.Err10 // CVK parity error (changed from Err01 to Err10 as per spec).
	}
	logDebug("CVK length and parity OK.")

	// Data after CVK part.
	remainingData := input[panStartIndex:]
	logDebug(
		fmt.Sprintf(
			"Remaining data (PAN field, expiry, service code): %s",
			logging.FormatData(
				remainingData,
			), // Replaced hex.EncodeToString with logging.FormatData.
		),
	)

	panDelimiterIndex := bytes.IndexByte(remainingData, ';')
	if panDelimiterIndex == -1 ||
		panDelimiterIndex == 0 { // PAN delimiter not found or PAN is empty.
		logDebug("Error: PAN delimiter not found or PAN is empty.")
		return nil, errorcodes.Err15 // Invalid PAN format.
	}
	// cryptoutils.GetVisaCVV expects PAN as a hex string.
	panHexStr := string(remainingData[:panDelimiterIndex])
	logDebug(fmt.Sprintf("PAN hex: %s", panHexStr))

	// Expected data after PAN (hex) + ';': 4N (expDate) + 3N (servCode) = 7 bytes.
	if len(remainingData) < panDelimiterIndex+1+4+3 {
		logDebug("Error: Not enough data for expDate and servCode.")
		return nil, errorcodes.Err15 // Not enough data for expDate and servCode.
	}

	expDateStr := string(remainingData[panDelimiterIndex+1 : panDelimiterIndex+1+4])
	servCodeStr := string(remainingData[panDelimiterIndex+1+4 : panDelimiterIndex+1+4+3])
	logDebug(fmt.Sprintf("Expiry date: %s, Service code: %s", expDateStr, servCodeStr))

	logDebug("Extending CVK to triple length for GetVisaCVV.")
	tripleLengthCVK, err := cryptoutils.ExtendDoubleToTripleKey(clearCVK)
	if err != nil {
		logDebug(fmt.Sprintf("Error extending CVK to triple length: %v", err))
		// Consider if a more specific error code is needed or if Err42 is appropriate.
		return nil, errorcodes.Err42 // Using Err42 for crypto operation failure.
	}
	logDebug(
		fmt.Sprintf("Triple-length CVK for GetVisaCVV: %s", logging.FormatData(tripleLengthCVK)),
	)

	logDebug("Calculating CVV...")
	// Calculate CVV using the utility function.
	// PAN is passed as a hex string, expDate and servCode as digit strings, cvk as raw bytes.
	cvvValueBytes, err := cryptoutils.GetVisaCVV(
		panHexStr,
		expDateStr,
		servCodeStr,
		tripleLengthCVK,
	)
	if err != nil {
		logDebug(fmt.Sprintf("Error calculating CVV: %v", err))
		// An error from GetVisaCVV could be due to various reasons (e.g., internal crypto error).
		// Map to Err42 (DES failure) or a more general crypto error.
		return nil, errorcodes.Err42
	}
	logDebug(
		fmt.Sprintf("Calculated CVV bytes: %s", logging.FormatData(cvvValueBytes)),
	) // Replaced hex.EncodeToString with logging.FormatData.

	// Format response: 'CX' + '00' + CVV
	response := make([]byte, 0, 2+len(errorcodes.Err00.CodeOnly())+len(cvvValueBytes))
	response = append(response, []byte("CX")...)
	response = append(response, []byte(errorcodes.Err00.CodeOnly())...)
	response = append(response, cvvValueBytes...)
	logDebug(
		fmt.Sprintf("Final response: %s", logging.FormatData(response)),
	) // Replaced hex.EncodeToString with logging.FormatData.

	return response, nil
}
