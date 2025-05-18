// Package logic implements HSM command business logic.
package logic

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/common"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// For testing: allow overriding the decrypt function.
var decryptUnderLMKFunc = decryptUnderLMK

// SetDecryptForTest replaces the LMK decryption function for testing and returns the original.
func SetDecryptForTest(
	f func([]byte, string, byte) ([]byte, error),
) (orig func([]byte, string, byte) ([]byte, error)) {
	orig = decryptUnderLMKFunc
	decryptUnderLMKFunc = f
	return orig
}

// ExecuteCY executes the CY command to verify a CVV.
func ExecuteCY(input []byte) ([]byte, error) {
	logInfo("CY: Starting CVV verification.")
	logDebug(
		fmt.Sprintf("CY: Input data: %s", common.FormatData(input)),
	)

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
		decryptedCVK, err := decryptUnderLMKFunc(encryptedCVKBytes, "402", 'U')
		if err != nil {
			logError(fmt.Sprintf("CY: CVK decryption failed: %v", err))
			if hsmErr, ok := err.(errorcodes.HSMError); ok {
				return nil, hsmErr
			}
			return nil, errorcodes.Err10
		}
		clearCVK = decryptedCVK
		logDebug(
			fmt.Sprintf("CY: Decrypted CVK value: %s", common.FormatData(clearCVK)),
		)
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

		// Decrypt and validate CVKA
		logInfo("CY: Decrypting CVKA under LMK.")
		decryptedCVKA, err := decryptUnderLMKFunc(encryptedCVKABytes, "402", 'X')
		if err != nil {
			logError(fmt.Sprintf("CY: CVKA decryption failed: %v", err))
			if hsmErr, ok := err.(errorcodes.HSMError); ok {
				return nil, hsmErr
			}
			return nil, errorcodes.Err10
		}
		if len(decryptedCVKA) != 8 {
			logError(fmt.Sprintf("CY: CVKA incorrect length: %d bytes", len(decryptedCVKA)))
			return nil, errorcodes.Err10
		}

		logInfo("CY: Verifying CVKA parity.")
		if !cryptoutils.CheckKeyParity(decryptedCVKA) {
			logError("CY: CVKA parity check failed")
			return nil, errorcodes.Err10
		}
		logDebug(fmt.Sprintf("CY: CVKA decrypted value: %s", common.FormatData(decryptedCVKA)))

		// Decrypt and validate CVKB
		logInfo("CY: Decrypting CVKB under LMK.")
		decryptedCVKB, err := decryptUnderLMKFunc(encryptedCVKBBytes, "402", 'X')
		if err != nil {
			logError(fmt.Sprintf("CY: CVKB decryption failed: %v", err))
			if hsmErr, ok := err.(errorcodes.HSMError); ok {
				return nil, hsmErr
			}
			return nil, errorcodes.Err10
		}
		if len(decryptedCVKB) != 8 {
			logError(fmt.Sprintf("CY: CVKB incorrect length: %d bytes", len(decryptedCVKB)))
			return nil, errorcodes.Err10
		}

		logInfo("CY: Verifying CVKB parity.")
		if !cryptoutils.CheckKeyParity(decryptedCVKB) {
			logError("CY: CVKB parity check failed")
			return nil, errorcodes.Err10
		}
		logDebug(fmt.Sprintf("CY: CVKB decrypted value: %s", common.FormatData(decryptedCVKB)))

		logInfo("CY: Combining key components.")
		clearCVK = append(decryptedCVKA, decryptedCVKB...)
		logDebug(fmt.Sprintf("CY: Combined CVK value: %s", common.FormatData(clearCVK)))
	}

	// Validate final CVK (both formats must result in valid double-length key)
	logInfo("CY: Validating final CVK.")
	logDebug(fmt.Sprintf("CY: Final CVK value: %s", common.FormatData(clearCVK)))

	if len(clearCVK) != 16 {
		logError(fmt.Sprintf("CY: CVK incorrect length: %d bytes, expected 16", len(clearCVK)))
		return nil, errorcodes.Err27
	}

	if !cryptoutils.CheckKeyParity(clearCVK) {
		logError("CY: Final CVK parity check failed")
		return nil, errorcodes.Err10
	}
	logInfo("CY: CVK validation successful.")

	// Parse CVV (3 bytes)
	logInfo("CY: Processing verification data.")
	if len(input) < cvvStartIndex+3 {
		logError("CY: Input data too short for CVV")
		return nil, errorcodes.Err15
	}
	cvvToVerify := input[cvvStartIndex : cvvStartIndex+3]
	remainingData := input[cvvStartIndex+3:]
	logDebug(fmt.Sprintf("CY: CVV to verify: %s", common.FormatData(cvvToVerify)))

	// Parse remaining fields
	panDelimiterIndex := bytes.IndexByte(remainingData, ';')
	if panDelimiterIndex == -1 || panDelimiterIndex == 0 {
		logError("CY: Invalid PAN format")
		return nil, errorcodes.Err15
	}
	panHexStr := string(remainingData[:panDelimiterIndex])
	logDebug(fmt.Sprintf("CY: PAN value: %s", panHexStr))

	if len(remainingData) < panDelimiterIndex+1+4+3 {
		logError("CY: Missing expiry date or service code")
		return nil, errorcodes.Err15
	}

	expDateStr := string(remainingData[panDelimiterIndex+1 : panDelimiterIndex+1+4])
	servCodeStr := string(remainingData[panDelimiterIndex+1+4 : panDelimiterIndex+1+4+3])
	logDebug(fmt.Sprintf("CY: Expiry date: %s, Service code: %s", expDateStr, servCodeStr))

	// Extend CVK to triple length for CVV calculation
	logInfo("CY: Preparing CVK for CVV verification.")
	tripleLengthCVK, err := cryptoutils.ExtendDoubleToTripleKey(clearCVK)
	if err != nil {
		logError(fmt.Sprintf("CY: Failed to extend CVK: %v", err))
		return nil, errorcodes.Err42
	}
	logDebug(
		fmt.Sprintf("CY: Extended CVK value: %s", common.FormatData(tripleLengthCVK)),
	)

	// Calculate CVV using the utility function
	logInfo("CY: Calculating verification CVV.")
	calculatedCVV, err := cryptoutils.GetVisaCVV(
		panHexStr,
		expDateStr,
		servCodeStr,
		tripleLengthCVK,
	)
	if err != nil {
		logError(fmt.Sprintf("CY: CVV calculation failed: %v", err))
		return nil, errorcodes.Err42
	}
	logDebug(fmt.Sprintf("CY: Generated CVV value: %s", common.FormatData(calculatedCVV)))

	// Compare CVVs and format response
	logInfo("CY: Verifying CVV match.")
	var errorCode string
	if bytes.Equal(cvvToVerify, calculatedCVV) {
		logInfo("CY: CVV verification successful.")
		errorCode = errorcodes.Err00.CodeOnly()
	} else {
		logError("CY: CVV verification failed")
		logDebug(fmt.Sprintf("CY: CVV mismatch - calculated: %s, provided: %s",
			common.FormatData(calculatedCVV), common.FormatData(cvvToVerify)))
		errorCode = errorcodes.Err01.CodeOnly()
	}

	logInfo("CY: Formatting response.")
	response := make([]byte, 0, 2+len(errorCode))
	response = append(response, []byte("CZ")...)
	response = append(response, []byte(errorCode)...)
	logDebug(fmt.Sprintf("CY: Final response: %s", common.FormatData(response)))

	return response, nil
}
