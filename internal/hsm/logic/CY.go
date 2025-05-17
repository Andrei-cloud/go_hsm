// Package logic implements HSM command business logic.
package logic

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/internal/logging"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteCY executes the CY command to verify a CVV.
func ExecuteCY(input []byte) ([]byte, error) {
	logDebug(
		fmt.Sprintf("ExecuteCY input: %s", logging.FormatData(input)),
	)

	// Minimum data length: CVK(32H or U+32H) + CVV(3N) + PAN(min 1N) + ';'(1) + expDate(4N) + servCode(3N) = 44/45 bytes
	const minDataLength = 32 + 3 + 1 + 1 + 4 + 3

	if len(input) < minDataLength {
		logDebug("Error: Input too short for minimum required fields.")
		return nil, errorcodes.Err15 // Not enough data.
	}

	var clearCVK []byte
	var cvvStartIndex int

	// First check for U-prefixed double-length CVK
	if input[0] == 'U' {
		// Case 1: 'U' prefixed - means an ENCRYPTED DOUBLE-LENGTH CVK is provided.
		// Format: U<32H_encrypted_CVK> + remaining_data...
		logDebug("CVK is U-prefixed: expecting encrypted double-length CVK.")
		if len(input) < 1+32 {
			logDebug("Error: Not enough data for U-prefixed encrypted double-length CVK.")
			return nil, errorcodes.Err15
		}

		cvkHexStr := string(input[1:33])
		cvvStartIndex = 33
		logDebug(fmt.Sprintf("Encrypted double-length CVK hex (U-prefixed): %s", cvkHexStr))

		encryptedCVKBytes, err := hex.DecodeString(cvkHexStr)
		if err != nil {
			logDebug(fmt.Sprintf("Error decoding U-prefixed encrypted CVK hex: %v", err))
			return nil, errorcodes.Err15 // Invalid CVK format.
		}

		logDebug("Decrypting U-prefixed double-length CVK using type '402' scheme 'U'...")
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
		// Format: <16H_encrypted_CVKA><16H_encrypted_CVKB> + remaining_data...
		logDebug("CVK is not U-prefixed: expecting a pair of encrypted single-length CVKs.")
		if len(input) < 32 {
			logDebug("Error: Not enough data for encrypted CVK pair.")
			return nil, errorcodes.Err15
		}

		cvkaHexStr := string(input[0:16])
		cvkbHexStr := string(input[16:32])
		cvvStartIndex = 32

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

		// Decrypt and validate CVKA
		logDebug("Decrypting CVKA using type '402' scheme 'X'...")
		decryptedCVKA, err := decryptUnderLMK(encryptedCVKABytes, "402", 'X')
		if err != nil {
			logDebug(fmt.Sprintf("Error decrypting CVKA: %v", err))
			if hsmErr, ok := err.(errorcodes.HSMError); ok {
				return nil, hsmErr
			}
			return nil, errorcodes.Err10 // Decryption failure.
		}
		if len(decryptedCVKA) != 8 {
			logDebug(fmt.Sprintf("Error: Decrypted CVKA is not single length (8 bytes). Length: %d", len(decryptedCVKA)))
			return nil, errorcodes.Err10 // Key component length error.
		}
		if !cryptoutils.CheckKeyParity(decryptedCVKA) {
			logDebug("Error: Decrypted CVKA parity check failed.")
			return nil, errorcodes.Err10 // CVK A or CVK B parity error.
		}
		logDebug(fmt.Sprintf("Decrypted CVKA: %s", logging.FormatData(decryptedCVKA)))

		// Decrypt and validate CVKB
		logDebug("Decrypting CVKB using type '402' scheme 'X'...")
		decryptedCVKB, err := decryptUnderLMK(encryptedCVKBBytes, "402", 'X')
		if err != nil {
			logDebug(fmt.Sprintf("Error decrypting CVKB: %v", err))
			if hsmErr, ok := err.(errorcodes.HSMError); ok {
				return nil, hsmErr
			}
			return nil, errorcodes.Err10 // Decryption failure.
		}
		if len(decryptedCVKB) != 8 {
			logDebug(fmt.Sprintf("Error: Decrypted CVKB is not single length (8 bytes). Length: %d", len(decryptedCVKB)))
			return nil, errorcodes.Err10 // Key component length error.
		}
		if !cryptoutils.CheckKeyParity(decryptedCVKB) {
			logDebug("Error: Decrypted CVKB parity check failed.")
			return nil, errorcodes.Err10 // CVK A or CVK B parity error.
		}
		logDebug(fmt.Sprintf("Decrypted CVKB: %s", logging.FormatData(decryptedCVKB)))

		clearCVK = append(decryptedCVKA, decryptedCVKB...)
		logDebug(fmt.Sprintf("Combined clear CVK from pair: %s", logging.FormatData(clearCVK)))
	}

	// Validate final CVK (both formats must result in valid double-length key)
	logDebug(fmt.Sprintf("Clear CVK for validation: %s", logging.FormatData(clearCVK)))
	logDebug("Validating clear CVK length and parity.")

	if len(clearCVK) != 16 {
		logDebug(fmt.Sprintf("Error: CVK length is %d, expected 16.", len(clearCVK)))
		return nil, errorcodes.Err27 // CVK not double length.
	}
	if !cryptoutils.CheckKeyParity(clearCVK) {
		logDebug("Error: CVK parity check failed.")
		return nil, errorcodes.Err10 // CVK parity error.
	}
	logDebug("CVK length and parity OK.")

	// Parse CVV (3 bytes)
	if len(input) < cvvStartIndex+3 {
		logDebug("Error: Not enough data for CVV after CVK.")
		return nil, errorcodes.Err15
	}
	cvvToVerify := input[cvvStartIndex : cvvStartIndex+3]
	remainingData := input[cvvStartIndex+3:]
	logDebug(fmt.Sprintf("CVV to verify: %s", logging.FormatData(cvvToVerify)))

	// Parse remaining fields
	panDelimiterIndex := bytes.IndexByte(remainingData, ';')
	if panDelimiterIndex == -1 || panDelimiterIndex == 0 {
		logDebug("Error: PAN delimiter not found or PAN is empty.")
		return nil, errorcodes.Err15 // Invalid PAN format.
	}
	panHexStr := string(remainingData[:panDelimiterIndex])
	logDebug(fmt.Sprintf("PAN hex: %s", panHexStr))

	if len(remainingData) < panDelimiterIndex+1+4+3 {
		logDebug("Error: Not enough data for expDate and servCode.")
		return nil, errorcodes.Err15
	}

	expDateStr := string(remainingData[panDelimiterIndex+1 : panDelimiterIndex+1+4])
	servCodeStr := string(remainingData[panDelimiterIndex+1+4 : panDelimiterIndex+1+4+3])
	logDebug(fmt.Sprintf("Expiry date: %s, Service code: %s", expDateStr, servCodeStr))

	// Extend CVK to triple length for CVV calculation
	logDebug("Extending CVK to triple length for GetVisaCVV.")
	tripleLengthCVK, err := cryptoutils.ExtendDoubleToTripleKey(clearCVK)
	if err != nil {
		logDebug(fmt.Sprintf("Error extending CVK to triple length: %v", err))
		return nil, errorcodes.Err42 // Using Err42 for crypto operation failure.
	}
	logDebug(
		fmt.Sprintf("Triple-length CVK for GetVisaCVV: %s", logging.FormatData(tripleLengthCVK)),
	)

	// Calculate CVV using the utility function
	logDebug("Calculating CVV for verification...")
	calculatedCVV, err := cryptoutils.GetVisaCVV(
		panHexStr,
		expDateStr,
		servCodeStr,
		tripleLengthCVK,
	)
	if err != nil {
		logDebug(fmt.Sprintf("Error calculating CVV: %v", err))
		return nil, errorcodes.Err42
	}
	logDebug(fmt.Sprintf("Calculated CVV: %s", logging.FormatData(calculatedCVV)))

	// Compare CVVs and format response
	var errorCode string
	if bytes.Equal(cvvToVerify, calculatedCVV) {
		logDebug("CVV verification successful.")
		errorCode = errorcodes.Err00.CodeOnly() // No error, CVV verified.
	} else {
		logDebug(fmt.Sprintf("CVV verification failed: calculated %s != provided %s",
			logging.FormatData(calculatedCVV), logging.FormatData(cvvToVerify)))
		errorCode = errorcodes.Err01.CodeOnly() // CVV failed verification.
	}

	response := make([]byte, 0, 2+len(errorCode))
	response = append(response, []byte("CZ")...)
	response = append(response, []byte(errorCode)...)
	logDebug(fmt.Sprintf("Final response: %s", logging.FormatData(response)))

	return response, nil
}
