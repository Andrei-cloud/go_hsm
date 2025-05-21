package logic

import (
	"crypto/des"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/internal/hsm"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
	"github.com/andrei-cloud/go_hsm/pkg/pinblock"
)

const (
	tpkSize       = 33
	pvkDoubleSize = 32
	pvkSingleSize = 16
	pinBlockSize  = 16
	fmtCodeSize   = 2
	accNumSize    = 12
	pvkiSize      = 1
	pvvSize       = 4
)

// ExecuteDC processes the DC (Verify PIN) command and returns response bytes.
// Format: [TPK scheme + key](optional) + PIN block + source format code + account number + PVKI + PVV.
func ExecuteDC(input []byte) ([]byte, error) {
	logInfo("DC: starting PIN verification using Visa PVV")
	data := input
	// Minimum length calculation:
	// TPK (48 for 24-byte key) + PIN Block (16) + Source PIN Block Format (2) +
	// Account Number (12) + PVKI (2) + PVV (8) = 88 bytes.
	if len(data) < 88 {
		logError(fmt.Sprintf("DC: input data too short: %d bytes", len(data)))
		return nil, errorcodes.Err15
	}

	var clearPINString string
	firstByte := data[0]
	var decryptedTPK []byte

	// Handle optional TPK
	if firstByte == 'U' {
		logInfo("DC: processing double-length TPK")
		// Extract and decrypt TPK
		tpkRaw, err := hex.DecodeString(string(data[1:tpkSize]))
		if err != nil {
			logError("DC: invalid TPK hex format")
			return nil, errorcodes.Err15
		}
		data = data[tpkSize:]

		// Decrypt and validate TPK under LMK pair 14-15
		logInfo("DC: decrypting TPK under LMK")
		decryptedTPK, err = LMKProviderInstance.DecryptUnderLMK(tpkRaw, "002", 'U')
		if err != nil {
			logError("DC: TPK decryption failed")
			return nil, errorcodes.Err68
		}

		logInfo("DC: verifying TPK parity")
		if !cryptoutils.CheckKeyParity(decryptedTPK) {
			logError("DC: TPK parity check failed")
			return nil, errorcodes.Err10
		}

		logDebug(fmt.Sprintf("DC: decrypted TPK value: %s", hex.EncodeToString(decryptedTPK)))
	} else if len(data) >= 16 {
		// Single length TPK without scheme
		logInfo("DC: processing single-length TPK")
		// Extract and decrypt TPK as single length
		tpkRaw, err := hex.DecodeString(string(data[:16]))
		if err != nil {
			logError("DC: invalid TPK hex format")
			return nil, errorcodes.Err15
		}
		data = data[16:]

		// Decrypt and validate TPK under LMK pair 14-15
		logInfo("DC: decrypting TPK under LMK")
		decryptedTPK, err = LMKProviderInstance.DecryptUnderLMK(tpkRaw, "002", 'X')
		if err != nil {
			logError("DC: TPK decryption failed")
			return nil, errorcodes.Err68
		}

		logInfo("DC: verifying TPK parity")
		if !cryptoutils.CheckKeyParity(decryptedTPK) {
			logError("DC: TPK parity check failed")
			return nil, errorcodes.Err10
		}
	}

	// Handle PVK extraction and validation
	if len(data) < pvkDoubleSize+1 { // Need 1 for scheme + 32 for hex key
		logError("DC: insufficient data for PVK key")
		return nil, errorcodes.Err15
	}

	// For PVK: Either 'U' + 32H or just 32H (two single keys)
	pvkScheme := data[0]
	var decryptedPVK []byte
	var pvkBytesToSkip int // Track how many bytes to skip after PVK processing

	if pvkScheme == 'U' {
		logInfo("DC: processing double-length PVK with scheme")
		// Double length key with 'U' scheme
		pvkData := data[1 : 1+pvkDoubleSize] // Read 32 hex chars after scheme
		rawPvk, err := hex.DecodeString(string(pvkData))
		if err != nil {
			logError("DC: invalid PVK hex format")
			return nil, errorcodes.Err15
		}

		// Decrypt PVK under LMK pair 14-15
		logInfo("DC: decrypting PVK under LMK")
		decryptedPVK, err = LMKProviderInstance.DecryptUnderLMK(rawPvk, "002", 'U')
		if err != nil {
			logError("DC: PVK decryption failed")
			return nil, errorcodes.Err68
		}

		// Check if double length key
		if len(decryptedPVK) != 16 {
			logError("DC: PVK must be double length")
			return nil, errorcodes.Err27
		}

		logInfo("DC: verifying PVK parity")
		// Check parity after decryption
		if !cryptoutils.CheckKeyParity(decryptedPVK) {
			logError("DC: PVK parity check failed")
			return nil, errorcodes.Err11
		}
		pvkBytesToSkip = 1 + pvkDoubleSize // Skip scheme + hex key
	} else {
		// Single length key pair format - process PVK A and PVK B
		logInfo("DC: processing PVK as two single-length components")
		// Ensure enough data for two single keys
		if len(data) < pvkDoubleSize { // Need 16 + 16 hex chars
			logError("DC: insufficient data for PVK components")
			return nil, errorcodes.Err15
		}

		// Split into PVK A and B components
		pvkAData := data[:pvkSingleSize]              // First 16 hex chars
		pvkBData := data[pvkSingleSize:pvkDoubleSize] // Second 16 hex chars

		// Decrypt PVK A
		logInfo("DC: decrypting first PVK component")
		encpvkA, err := hex.DecodeString(string(pvkAData))
		if err != nil {
			logError("DC: invalid first PVK component hex format")
			return nil, errorcodes.Err15
		}
		decryptedPVKA, err := LMKProviderInstance.DecryptUnderLMK(encpvkA, "002", 'X')
		if err != nil {
			logError("DC: first PVK component decryption failed")
			return nil, errorcodes.Err68
		}

		logInfo("DC: verifying first PVK component parity")
		// Check PVK A parity after decryption
		if !cryptoutils.CheckKeyParity(decryptedPVKA) {
			logError("DC: first PVK component parity check failed")
			return nil, errorcodes.Err11
		}

		logDebug(fmt.Sprintf("DC: first PVK component: %s", hex.EncodeToString(decryptedPVKA)))

		// Decrypt PVK B
		logInfo("DC: decrypting second PVK component")
		encpvkB, err := hex.DecodeString(string(pvkBData))
		if err != nil {
			logError("DC: invalid second PVK component hex format")
			return nil, errorcodes.Err15
		}
		decryptedPVKB, err := LMKProviderInstance.DecryptUnderLMK(encpvkB, "002", 'X')
		if err != nil {
			logError("DC: second PVK component decryption failed")
			return nil, errorcodes.Err68
		}

		logInfo("DC: verifying second PVK component parity")
		// Check PVK B parity after decryption
		if !cryptoutils.CheckKeyParity(decryptedPVKB) {
			logError("DC: second PVK component parity check failed")
			return nil, errorcodes.Err11
		}

		logDebug(fmt.Sprintf("DC: second PVK component: %s", hex.EncodeToString(decryptedPVKB)))

		// Combine PVK A and PVK B for final PVK (16 raw bytes)
		logInfo("DC: combining PVK components")
		decryptedPVK = slices.Concat(decryptedPVK, decryptedPVKB)

		pvkBytesToSkip = pvkDoubleSize // Skip the two hex keys (16+16)
	}

	// Move to the next field after PVK
	data = data[pvkBytesToSkip:]

	// Extract and validate remaining fields
	if len(data) < pinBlockSize+fmtCodeSize+accNumSize+pvkiSize+pvvSize {
		logError("DC: insufficient data for remaining fields")
		return nil, errorcodes.Err15
	}

	// Extract encrypted PIN block and remaining fields
	logInfo("DC: extracting remaining input fields")
	encryptedPinBlockHex := string(data[:pinBlockSize])
	data = data[pinBlockSize:]
	logDebug(fmt.Sprintf("DC: encrypted PIN block value: %s", encryptedPinBlockHex))

	formatCode := string(data[:fmtCodeSize])
	data = data[fmtCodeSize:]
	logDebug(fmt.Sprintf("DC: format code: %s", formatCode))

	accountNum := string(data[:accNumSize])
	data = data[accNumSize:]
	logDebug(fmt.Sprintf("DC: account number: %s", accountNum))

	pvki := string(data[:pvkiSize])
	data = data[pvkiSize:]
	logDebug(fmt.Sprintf("DC: PVKI: %s", pvki))

	pvv := string(data[:pvvSize])
	logDebug(fmt.Sprintf("DC: received PVV: %s", pvv))

	// If TPK was present, decrypt the PIN block using TPK
	var pinBlockForClearHex string
	if decryptedTPK != nil {
		logInfo("DC: preparing TPK for PIN block decryption")
		// Prepare TPK for 3DES operation
		var fullTPK []byte
		switch len(decryptedTPK) {
		case 16:
			// Double length key - use as is, with last 8 bytes repeated
			fullTPK = make([]byte, 24)
			copy(fullTPK, decryptedTPK)
			copy(fullTPK[16:], decryptedTPK[:8])
			logDebug("DC: using double-length TPK")
		case 8:
			// Single length key - repeat it three times
			fullTPK = make([]byte, 24)
			copy(fullTPK, decryptedTPK)
			copy(fullTPK[8:], decryptedTPK)
			copy(fullTPK[16:], decryptedTPK)
			logDebug("DC: extended single-length TPK to triple-length")
		default:
			logError(fmt.Sprintf("DC: invalid TPK length: %d", len(decryptedTPK)))
			return nil, errorcodes.Err68
		}

		// Create TPK cipher
		tpkCipher, err := des.NewTripleDESCipher(fullTPK)
		if err != nil {
			logError("DC: failed to create TPK cipher")
			return nil, errorcodes.Err68
		}

		// Convert PIN block from hex to binary
		pinBlockBin, err := hex.DecodeString(encryptedPinBlockHex)
		if err != nil {
			logError("DC: invalid PIN block hex format")
			return nil, errorcodes.Err15
		}
		logDebug(fmt.Sprintf("DC: PIN block binary length: %d", len(pinBlockBin)))

		// Decrypt PIN block using TPK
		logInfo("DC: decrypting PIN block with TPK")
		decryptedPinBlock := make([]byte, len(pinBlockBin))
		tpkCipher.Decrypt(decryptedPinBlock, pinBlockBin)
		pinBlockForClearHex = hex.EncodeToString(decryptedPinBlock)
		logDebug(fmt.Sprintf("DC: decrypted PIN block value: %s", pinBlockForClearHex))
	} else {
		// PIN block is already decrypted under PVK or other key
		pinBlockForClearHex = encryptedPinBlockHex
		logDebug(fmt.Sprintf("DC: using PIN block as is: %s", pinBlockForClearHex))
	}

	// Extract clear PIN from decrypted PIN block
	logInfo("DC: validating PIN block format")
	pinBlockFormat, err := hsm.GetPinBlockFormatFromThalesCode(formatCode)
	if err != nil {
		logError(fmt.Sprintf("DC: invalid PIN block format code: %s", formatCode))
		return nil, errorcodes.Err23
	}

	logInfo("DC: extracting clear PIN from PIN block")
	clearPINString, err = pinblock.DecodePinBlock(pinBlockForClearHex, accountNum, pinBlockFormat)
	if err != nil {
		logError("DC: failed to extract clear PIN")
		return nil, errorcodes.Err20
	}
	logDebug(fmt.Sprintf("DC: extracted PIN length: %d", len(clearPINString)))

	// Calculate PVV using clear PIN
	logInfo("DC: calculating PVV with extracted PIN")
	calculatedPVV, err := cryptoutils.GetVisaPVV(
		accountNum,
		pvki,
		clearPINString,
		decryptedPVK,
	)
	if err != nil {
		logError("DC: failed to calculate PVV")
		return nil, errorcodes.Err68
	}
	logDebug(fmt.Sprintf("DC: calculated PVV value: %s", string(calculatedPVV)))

	// Validate calculated PVV against received PVV
	logInfo("DC: validating calculated PVV against input")
	if string(calculatedPVV) != pvv {
		logError("DC: PVV verification failed")
		return nil, errorcodes.Err01
	}

	logInfo("DC: PIN verification completed successfully")

	response := "DD" + errorcodes.Err00.CodeOnly()

	return []byte(response), nil
}
