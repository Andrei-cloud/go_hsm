// Package logic implements HSM command business logic.
package logic

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/common"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteCY executes the CY command to verify a CVV.
func ExecuteCY(input []byte) ([]byte, error) {
	logInfo("CY: Starting CVV verification.")
	logDebug(fmt.Sprintf("CY: Input data: %s", common.FormatData(input)))

	// Minimum data length: CVK(32H or U+32H) + CVV(3N) + PAN(min 1N) + ';'(1) + expDate(4N) + servCode(3N) = 44/45 bytes
	const minDataLength = 32 + 3 + 1 + 1 + 4 + 3

	if len(input) < minDataLength {
		logError("CY: Input data too short")
		return nil, errorcodes.Err15
	}

	var clearCVK []byte
	var cvvStartIndex int

	// First check for U-prefixed double-length CVK
	if input[0] == 'U' {
		// Case 1: 'U' prefixed - means an ENCRYPTED DOUBLE-LENGTH CVK is provided.
		// Format: U<32H_encrypted_CVK> + remaining_data...
		logInfo("CY: Processing double-length encrypted CVK.")
		if len(input) < 1+32 {
			logError("CY: Input data too short for double-length CVK")
			return nil, errorcodes.Err15
		}

		cvkHexStr := string(input[1:33])
		cvvStartIndex = 33
		logDebug(fmt.Sprintf("CY: Encrypted CVK (hex): %s", cvkHexStr))

		encryptedCVKBytes, err := hex.DecodeString(cvkHexStr)
		if err != nil {
			logError("CY: Invalid CVK format")
			return nil, errorcodes.Err15
		}

		logInfo("CY: Decrypting CVK under LMK.")
		decryptedCVK, err := decryptUnderLMK(encryptedCVKBytes, "402", 'U')
		if err != nil {
			logError(fmt.Sprintf("CY: CVK decryption failed: %v", err))
			if hsmErr, ok := err.(errorcodes.HSMError); ok {
				return nil, hsmErr
			}

			return nil, errorcodes.Err10
		}
		clearCVK = decryptedCVK
		logDebug(fmt.Sprintf("CY: Decrypted CVK value: %s", common.FormatData(clearCVK)))
	} else {
		// Case 2: Not 'U' prefixed - means a PAIR OF ENCRYPTED SINGLE-LENGTH CVKs is PROVIDED.
		// Format: <16H_encrypted_CVKA><16H_encrypted_CVKB> + remaining_data...
		logInfo("CY: Processing CVK key pair.")
		if len(input) < 32 {
			logError("CY: Input data too short for CVK pair")
			return nil, errorcodes.Err15
		}

		cvkaHexStr := string(input[0:16])
		cvkbHexStr := string(input[16:32])
		cvvStartIndex = 32

		logDebug(fmt.Sprintf("CY: CVKA encrypted (hex): %s", cvkaHexStr))
		logDebug(fmt.Sprintf("CY: CVKB encrypted (hex): %s", cvkbHexStr))

		encryptedCVKABytes, err := hex.DecodeString(cvkaHexStr)
		if err != nil {
			logError("CY: Invalid CVKA format")
			return nil, errorcodes.Err15
		}

		encryptedCVKBBytes, err := hex.DecodeString(cvkbHexStr)
		if err != nil {
			logError("CY: Invalid CVKB format")
			return nil, errorcodes.Err15
		}

		logInfo("CY: Decrypting CVKA under LMK.")
		// Key Type "402" for CVK, Scheme 'X' for single-length key.
		decryptedCVKA, err := decryptUnderLMK(encryptedCVKABytes, "402", 'X')
		if err != nil {
			logError(fmt.Sprintf("CY: CVKA decryption failed: %v", err))
			if hsmErr, ok := err.(errorcodes.HSMError); ok {
				return nil, hsmErr
			}

			return nil, errorcodes.Err10
		}

		logInfo("CY: Verifying CVKA parity.")
		if !cryptoutils.CheckKeyParity(decryptedCVKA) {
			logError("CY: CVKA parity check failed")

			return nil, errorcodes.Err10
		}
		logDebug(fmt.Sprintf("CY: CVKA decrypted value: %s", common.FormatData(decryptedCVKA)))
		if len(decryptedCVKA) != 8 {
			logError(fmt.Sprintf("CY: CVKA incorrect length: %d bytes", len(decryptedCVKA)))

			return nil, errorcodes.Err10
		}

		logInfo("CY: Decrypting CVKB under LMK.")
		decryptedCVKB, err := decryptUnderLMK(encryptedCVKBBytes, "402", 'X')
		if err != nil {
			logError(fmt.Sprintf("CY: CVKB decryption failed: %v", err))
			if hsmErr, ok := err.(errorcodes.HSMError); ok {
				return nil, hsmErr
			}

			return nil, errorcodes.Err10
		}
		logInfo("CY: Verifying CVKB parity.")
		if !cryptoutils.CheckKeyParity(decryptedCVKB) {
			logError("CY: CVKB parity check failed")

			return nil, errorcodes.Err10
		}
		logDebug(fmt.Sprintf("CY: CVKB decrypted value: %s", common.FormatData(decryptedCVKB)))
		if len(decryptedCVKB) != 8 {
			logError(fmt.Sprintf("CY: CVKB incorrect length: %d bytes", len(decryptedCVKB)))

			return nil, errorcodes.Err10
		}

		logInfo("CY: Combining key components.")
		clearCVK = slices.Concat(decryptedCVKA, decryptedCVKB)
		logDebug(fmt.Sprintf("CY: Combined CVK value: %s", common.FormatData(clearCVK)))
	}

	logInfo("CY: Validating final CVK.")
	logDebug(fmt.Sprintf("CY: Final CVK value: %s", common.FormatData(clearCVK)))

	// CVK for Visa CVV must be 16 bytes (double-length DES key).
	if len(clearCVK) != 16 {
		logError(fmt.Sprintf("CY: CVK incorrect length: %d bytes, expected 16", len(clearCVK)))

		return nil, errorcodes.Err27
	}

	if !cryptoutils.CheckKeyParity(clearCVK) {
		logError("CY: Final CVK parity check failed")

		return nil, errorcodes.Err10
	}
	logInfo("CY: CVK validation successful.")

	// Extract received CVV
	cvv := string(input[cvvStartIndex : cvvStartIndex+3])
	logDebug(fmt.Sprintf("CY: Received CVV value: %s", cvv))

	// Process remaining data (account data after CVV)
	remainingData := input[cvvStartIndex+3:]
	logDebug(fmt.Sprintf("CY: Remaining data: %s", common.FormatData(remainingData)))

	// Find PAN delimiter
	panDelimiterIndex := bytes.IndexByte(remainingData, ';')
	if panDelimiterIndex == -1 || panDelimiterIndex == 0 {
		logError("CY: Invalid PAN format")
		return nil, errorcodes.Err15
	}

	// cryptoutils.GetVisaCVV expects PAN as a hex string.
	panHexStr := string(remainingData[:panDelimiterIndex])
	logDebug(fmt.Sprintf("CY: PAN value: %s", panHexStr))

	// Expected data after PAN (hex) + ';': 4N (expDate) + 3N (servCode) = 7 bytes.
	if len(remainingData) < panDelimiterIndex+1+4+3 {
		logError("CY: Missing expiry date or service code")
		return nil, errorcodes.Err15
	}

	expDateStr := string(remainingData[panDelimiterIndex+1 : panDelimiterIndex+1+4])
	servCodeStr := string(remainingData[panDelimiterIndex+1+4 : panDelimiterIndex+1+4+3])
	logDebug(fmt.Sprintf("CY: Expiry date: %s, Service code: %s", expDateStr, servCodeStr))

	logInfo("CY: Preparing CVK for CVV calculation.")
	tripleLengthCVK, err := cryptoutils.ExtendDoubleToTripleKey(clearCVK)
	if err != nil {
		logError(fmt.Sprintf("CY: Failed to extend CVK: %v", err))
		return nil, errorcodes.Err42
	}
	logDebug(
		fmt.Sprintf("Triple-length CVK for verification: %s", common.FormatData(tripleLengthCVK)),
	)

	logInfo("CY: Calculating CVV for verification.")
	// Calculate CVV using the utility function.
	// PAN is passed as a hex string, expDate and servCode as digit strings, cvk as raw bytes.
	calculatedCVV, err := cryptoutils.GetVisaCVV(
		panHexStr,
		expDateStr,
		servCodeStr,
		tripleLengthCVK,
	)
	if err != nil {
		logError(fmt.Sprintf("CY: Error calculating CVV: %v", err))
		// An error from GetVisaCVV could be due to various reasons (e.g., internal crypto error).
		// Map to Err42 (DES failure) or a more general crypto error.

		return nil, errorcodes.Err42
	}

	logDebug(fmt.Sprintf("CY: Calculated CVV: %s, Received CVV: %s", string(calculatedCVV), cvv))

	// Compare calculated CVV with received CVV
	if string(calculatedCVV) != cvv {
		logError("CY: CVV verification failed")

		return nil, errorcodes.Err01
	}

	logInfo("CY: CVV verification successful.")

	return []byte("CZ00"), nil
}
