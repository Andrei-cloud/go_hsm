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

// ExecuteCW executes the CW command to generate a CVV.
func ExecuteCW(input []byte) ([]byte, error) {
	logInfo("CW: Starting CVV generation.")
	logDebug(
		fmt.Sprintf("CW: Input data: %s", common.FormatData(input)),
	)

	var cvkHexStr string
	var panStartIndex int
	var clearCVK []byte // This will hold the CVK after potential decryption.

	// Minimum data length after key part: PAN_hex (13..19) + ';' (1) + expDate (4) + servCode (3) = 9 bytes.
	const minDataLengthAfterKey = 13 + 1 + 4 + 3

	if len(input) > 0 && input[0] == 'U' {
		// Case 1: 'U' prefixed - means an ENCRYPTED DOUBLE-LENGTH CVK is provided.
		// Format: U<32H_encrypted_CVK> + PAN_data...
		logInfo("CW: Processing double-length encrypted CVK.")
		// Min length: 1('U') + 32(EncCVK_hex) + minDataLengthAfterKey
		if len(input) < 1+32+minDataLengthAfterKey {
			logError("CW: Input data too short for double-length CVK")
			return nil, errorcodes.Err15
		}
		cvkHexStr = string(input[1 : 1+32])
		panStartIndex = 1 + 32
		logDebug(fmt.Sprintf("CW: Encrypted CVK (hex): %s", cvkHexStr))

		encryptedCVKBytes, err := hex.DecodeString(cvkHexStr)
		if err != nil {
			logError("CW: Invalid CVK format")
			return nil, errorcodes.Err15
		}

		logInfo("CW: Decrypting CVK under LMK.")
		// Key Type "402" for CVK, Scheme 'U' for double-length key.
		decryptedCVK, err := LMKProviderInstance.DecryptUnderLMK(encryptedCVKBytes, "402", 'U')
		if err != nil {
			logError(fmt.Sprintf("CW: CVK decryption failed: %v", err))
			if hsmErr, ok := err.(errorcodes.HSMError); ok {
				return nil, hsmErr
			}

			return nil, errorcodes.Err10
		}
		clearCVK = decryptedCVK
		logDebug(
			fmt.Sprintf("CW: Decrypted CVK: %s", common.FormatData(clearCVK)),
		)
	} else {
		// Case 2: Not 'U' prefixed - means a PAIR OF ENCRYPTED SINGLE-LENGTH CVKs is PROVIDED.
		// Format: <16H_encrypted_CVKA><16H_encrypted_CVKB> + PAN_data...
		logInfo("CW: Processing CVK key pair.")
		// Min length: 16(EncCVKA_hex) + 16(EncCVKB_hex) + minDataLengthAfterKey
		if len(input) < 16+16+minDataLengthAfterKey {
			logError("CW: Input data too short for CVK pair")
			return nil, errorcodes.Err15
		}

		cvkaHexStr := string(input[0:16])
		cvkbHexStr := string(input[16:32])
		panStartIndex = 32 // Data starts after the 32 hex chars of the key pair.

		logDebug(fmt.Sprintf("CW: CVKA encrypted (hex): %s", cvkaHexStr))
		logDebug(fmt.Sprintf("CW: CVKB encrypted (hex): %s", cvkbHexStr))

		encryptedCVKABytes, err := hex.DecodeString(cvkaHexStr)
		if err != nil {
			logError("CW: Invalid CVKA format")
			return nil, errorcodes.Err15
		}

		encryptedCVKBBytes, err := hex.DecodeString(cvkbHexStr)
		if err != nil {
			logError("CW: Invalid CVKB format")
			return nil, errorcodes.Err15
		}

		logInfo("CW: Decrypting CVKA under LMK.")
		// Key Type "402" for CVK, Scheme 'X' for single-length key.
		decryptedCVKA, err := LMKProviderInstance.DecryptUnderLMK(encryptedCVKABytes, "402", 'X')
		if err != nil {
			logError(fmt.Sprintf("CW: CVKA decryption failed: %v", err))
			if hsmErr, ok := err.(errorcodes.HSMError); ok {
				return nil, hsmErr
			}

			return nil, errorcodes.Err10
		}

		logInfo("CW: Verifying CVKA parity.")
		if !cryptoutils.CheckKeyParity(decryptedCVKA) {
			logError("CW: CVKA parity check failed")

			return nil, errorcodes.Err10
		}
		logDebug(fmt.Sprintf("CW: CVKA decrypted value: %s", common.FormatData(decryptedCVKA)))
		if len(decryptedCVKA) != 8 {
			logError(fmt.Sprintf("CW: CVKA incorrect length: %d bytes", len(decryptedCVKA)))

			return nil, errorcodes.Err10
		}

		logInfo("CW: Decrypting CVKB under LMK.")
		decryptedCVKB, err := LMKProviderInstance.DecryptUnderLMK(encryptedCVKBBytes, "402", 'X')
		if err != nil {
			logError(fmt.Sprintf("CW: CVKB decryption failed: %v", err))
			if hsmErr, ok := err.(errorcodes.HSMError); ok {
				return nil, hsmErr
			}

			return nil, errorcodes.Err10
		}
		logInfo("CW: Verifying CVKB parity.")
		if !cryptoutils.CheckKeyParity(decryptedCVKB) {
			logError("CW: CVKB parity check failed")

			return nil, errorcodes.Err10
		}
		logDebug(fmt.Sprintf("CW: CVKB decrypted value: %s", common.FormatData(decryptedCVKB)))
		if len(decryptedCVKB) != 8 {
			logError(fmt.Sprintf("CW: CVKB incorrect length: %d bytes", len(decryptedCVKB)))
			return nil, errorcodes.Err10
		}

		logInfo("CW: Combining key components.")
		// combining CVKA and CVKB into a double-length CVK.
		clearCVK = slices.Concat(decryptedCVKA, decryptedCVKB)
		logDebug(fmt.Sprintf("CW: Combined CVK value: %s", common.FormatData(clearCVK)))
	}

	logInfo("CW: Validating final CVK.")
	logDebug(fmt.Sprintf("CW: Final CVK value: %s", common.FormatData(clearCVK)))

	// CVK for Visa CVV must be 16 bytes (double-length DES key).
	if len(clearCVK) != 16 {
		logError(fmt.Sprintf("CW: CVK incorrect length: %d bytes, expected 16", len(clearCVK)))
		return nil, errorcodes.Err27
	}

	if !cryptoutils.CheckKeyParity(clearCVK) {
		logError("CW: Final CVK parity check failed")
		return nil, errorcodes.Err10
	}
	logInfo("CW: CVK validation successful.")

	// Data after CVK part.
	logInfo("CW: Processing card data.")
	remainingData := input[panStartIndex:]
	logDebug(fmt.Sprintf("CW: Card data input: %s", common.FormatData(remainingData)))

	panDelimiterIndex := bytes.IndexByte(remainingData, ';')
	if panDelimiterIndex == -1 || panDelimiterIndex == 0 {
		logError("CW: Invalid PAN format - missing delimiter")
		return nil, errorcodes.Err15
	}

	// cryptoutils.GetVisaCVV expects PAN as a hex string.
	panHexStr := string(remainingData[:panDelimiterIndex])
	panLength := len(panHexStr)
	if panLength < 13 || panLength > 19 {
		logError(fmt.Sprintf("CW: Invalid PAN length: %d, must be between 13 and 19", panLength))
		return nil, errorcodes.Err15
	}
	logDebug(fmt.Sprintf("CW: PAN value: %s, length: %d", panHexStr, panLength))

	// Expected data after PAN (hex) + ';': 4N (expDate) + 3N (servCode) = 7 bytes.
	if len(remainingData) < panDelimiterIndex+1+4+3 {
		logError("CW: Missing expiry date or service code")
		return nil, errorcodes.Err15
	}

	expDateStr := string(remainingData[panDelimiterIndex+1 : panDelimiterIndex+1+4])
	servCodeStr := string(remainingData[panDelimiterIndex+1+4 : panDelimiterIndex+1+4+3])
	logDebug(fmt.Sprintf("CW: Expiry date: %s, Service code: %s", expDateStr, servCodeStr))

	logInfo("CW: Preparing CVK for CVV calculation.")
	tripleLengthCVK, err := cryptoutils.ExtendDoubleToTripleKey(clearCVK)
	if err != nil {
		logError(fmt.Sprintf("CW: Failed to extend CVK: %v", err))
		return nil, errorcodes.Err42
	}
	logDebug(
		fmt.Sprintf("Triple-length CVK for GetVisaCVV: %s", common.FormatData(tripleLengthCVK)),
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
	logInfo("CW: CVV calculation complete.")
	logDebug(fmt.Sprintf("CW: Generated CVV value: %s", common.FormatData(cvvValueBytes)))

	// Format response: 'CX' + '00' + CVV
	logInfo("CW: Formatting response.")

	response := slices.Concat([]byte("CX00"), cvvValueBytes)
	logDebug(fmt.Sprintf("CW: Final response: %s", common.FormatData(response)))

	return response, nil
}
