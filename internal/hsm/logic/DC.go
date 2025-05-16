package logic

import (
	"crypto/des"
	"encoding/hex"
	"fmt"

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
	data := input
	// Minimum length calculation:
	// TPK (48 for 24-byte key) + PIN Block (16) + Source PIN Block Format (2) +
	// Account Number (12) + PVKI (2) + PVV (8) = 88 bytes.
	if len(data) < 88 {
		logDebug(
			fmt.Sprintf("DC: insufficient data length, expected at least 88, got %d", len(data)),
		)

		return nil, errorcodes.Err15
	}

	var clearPINString string
	firstByte := data[0]
	var decryptedTPK []byte

	// Handle optional TPK
	if firstByte == 'U' {
		// Extract and decrypt TPK
		tpkRaw, err := hex.DecodeString(string(data[1:tpkSize]))
		if err != nil {
			logDebug(fmt.Sprintf("DC: invalid TPK hex format: %v", err))

			return nil, errorcodes.Err15
		}
		data = data[tpkSize:]

		// Decrypt and validate TPK under LMK pair 14-15
		decryptedTPK, err = decryptUnderLMK(tpkRaw, "002", 'U')
		if err != nil {
			logDebug(fmt.Sprintf("DC: failed to decrypt TPK: %v", err))

			return nil, errorcodes.Err68
		}

		if !cryptoutils.CheckKeyParity(decryptedTPK) {
			logDebug("DC: decrypted TPK parity error")

			return nil, errorcodes.Err10
		}
	} else if len(data) >= 16 { // Single length TPK without scheme
		// Extract and decrypt TPK as single length
		tpkRaw, err := hex.DecodeString(string(data[:16]))
		if err != nil {
			logDebug(fmt.Sprintf("DC: invalid TPK hex format: %v", err))

			return nil, errorcodes.Err15
		}
		data = data[16:]

		// Decrypt and validate TPK under LMK pair 14-15
		decryptedTPK, err = decryptUnderLMK(tpkRaw, "002", 'X')
		if err != nil {
			logDebug(fmt.Sprintf("DC: failed to decrypt TPK: %v", err))

			return nil, errorcodes.Err68
		}

		if !cryptoutils.CheckKeyParity(decryptedTPK) {
			logDebug("DC: decrypted TPK parity error")

			return nil, errorcodes.Err10
		}
	}

	// Handle PVK extraction and validation
	if len(data) < pvkDoubleSize+1 { // Need 1 for scheme + 32 for hex key
		logDebug("DC: insufficient data for PVK")

		return nil, errorcodes.Err15
	}

	// For PVK: Either 'U' + 32H or just 32H (two single keys)
	pvkScheme := data[0]
	var decryptedPVK []byte
	var pvkBytesToSkip int // Track how many bytes to skip after PVK processing

	if pvkScheme == 'U' {
		// Double length key with 'U' scheme
		pvkData := data[1 : 1+pvkDoubleSize] // Read 32 hex chars after scheme
		rawPvk, err := hex.DecodeString(string(pvkData))
		if err != nil {
			logDebug(fmt.Sprintf("DC: invalid PVK hex format: %v", err))

			return nil, errorcodes.Err15
		}

		// Decrypt PVK under LMK pair 14-15
		decryptedPVK, err = decryptUnderLMK(rawPvk, "002", 'U')
		if err != nil {
			logDebug(fmt.Sprintf("DC: failed to decrypt PVK: %v", err))

			return nil, errorcodes.Err68
		}

		// Check if double length key
		if len(decryptedPVK) != 16 {
			logDebug("DC: PVK must be double length")

			return nil, errorcodes.Err27
		}

		// Check parity after decryption
		if !cryptoutils.CheckKeyParity(decryptedPVK) {
			logDebug("DC: decrypted PVK parity error")

			return nil, errorcodes.Err11
		}
		pvkBytesToSkip = 1 + pvkDoubleSize // Skip scheme + hex key
	} else {
		// Single length key pair format - process PVK A and PVK B
		// Ensure enough data for two single keys
		if len(data) < pvkDoubleSize { // Need 16 + 16 hex chars
			logDebug("DC: insufficient data for PVK pair")

			return nil, errorcodes.Err15
		}

		// Split into PVK A and B components
		pvkAData := data[:pvkSingleSize]              // First 16 hex chars
		pvkBData := data[pvkSingleSize:pvkDoubleSize] // Second 16 hex chars.

		// Decrypt PVK A.
		encpvkA, err := hex.DecodeString(string(pvkAData))
		if err != nil {
			logDebug(fmt.Sprintf("DC: invalid PVK A hex format: %v", err))

			return nil, errorcodes.Err15
		}
		decryptedPVKA, err := decryptUnderLMK(encpvkA, "002", 'X')
		if err != nil {
			logDebug(fmt.Sprintf("DC: failed to decrypt PVK A: %v", err))

			return nil, errorcodes.Err68
		}

		// Check PVK A parity after decryption.
		if !cryptoutils.CheckKeyParity(decryptedPVKA) {
			logDebug("DC: decrypted PVK A parity error")

			return nil, errorcodes.Err11
		}

		// Log clear value of PVK A.
		logDebug(fmt.Sprintf("DC: clear PVK A: %s", hex.EncodeToString(decryptedPVKA)))

		// Decrypt PVK B.
		encpvkB, err := hex.DecodeString(string(pvkBData))
		if err != nil {
			logDebug(fmt.Sprintf("DC: invalid PVK B hex format: %v", err))

			return nil, errorcodes.Err15
		}
		decryptedPVKB, err := decryptUnderLMK(encpvkB, "002", 'X')
		if err != nil {
			logDebug(fmt.Sprintf("DC: failed to decrypt PVK B: %v", err))

			return nil, errorcodes.Err68
		}

		// Check PVK B parity after decryption.
		if !cryptoutils.CheckKeyParity(decryptedPVKB) {
			logDebug("DC: decrypted PVK B parity error")

			return nil, errorcodes.Err11
		}

		// Log clear value of PVK B.
		logDebug(fmt.Sprintf("DC: clear PVK B: %s", hex.EncodeToString(decryptedPVKB)))

		// Combine PVK A and PVK B for final PVK (16 raw bytes)
		decryptedPVK = append(decryptedPVKA, decryptedPVKB...)
		pvkBytesToSkip = pvkDoubleSize // Skip the two hex keys (16+16).
	}

	// Move to the next field after PVK
	data = data[pvkBytesToSkip:]

	// Extract and validate remaining fields
	if len(data) < pinBlockSize+fmtCodeSize+accNumSize+pvkiSize+pvvSize {
		logDebug("DC: insufficient data for remaining fields")

		return nil, errorcodes.Err15
	}

	// Extract encrypted PIN block
	encryptedPinBlockHex := string(data[:pinBlockSize])
	data = data[pinBlockSize:]
	logDebug(fmt.Sprintf("DC: parsed encrypted PIN block: %s", encryptedPinBlockHex))

	// Skip format code
	formatCode := string(data[:fmtCodeSize])
	data = data[fmtCodeSize:]
	logDebug(fmt.Sprintf("DC: parsed format code: %s", formatCode))

	accountNum := string(data[:accNumSize])
	data = data[accNumSize:]
	logDebug(fmt.Sprintf("DC: parsed account number: %s", accountNum))

	pvki := string(data[:pvkiSize])
	data = data[pvkiSize:]
	logDebug(fmt.Sprintf("DC: parsed PVKI: %s", pvki))

	pvv := string(data[:pvvSize])
	logDebug(fmt.Sprintf("DC: parsed PVV: %s", pvv))

	// If TPK was present, decrypt the PIN block using TPK
	var pinBlockForClearHex string
	if decryptedTPK != nil {
		logDebug(fmt.Sprintf("DC: processing with TPK present, TPK length: %d", len(decryptedTPK)))
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
			logDebug(fmt.Sprintf("DC: invalid TPK length: %d", len(decryptedTPK)))
			return nil, errorcodes.Err68
		}

		// Create TPK cipher
		tpkCipher, err := des.NewTripleDESCipher(fullTPK)
		if err != nil {
			logDebug(fmt.Sprintf("DC: failed to create TPK cipher: %v", err))

			return nil, errorcodes.Err68
		}

		// Convert PIN block from hex to binary
		pinBlockBin, err := hex.DecodeString(encryptedPinBlockHex)
		if err != nil {
			logDebug(fmt.Sprintf("DC: invalid PIN block hex format: %v", err))

			return nil, errorcodes.Err15
		}
		logDebug(fmt.Sprintf("DC: decoded PIN block binary length: %d", len(pinBlockBin)))

		// Decrypt PIN block using TPK
		decryptedPinBlock := make([]byte, len(pinBlockBin))
		tpkCipher.Decrypt(decryptedPinBlock, pinBlockBin)
		pinBlockForClearHex = hex.EncodeToString(decryptedPinBlock)
		logDebug(fmt.Sprintf("DC: decrypted PIN block hex: %s", pinBlockForClearHex))
		logDebug(fmt.Sprintf("DC: account number for PIN extraction: %s", accountNum))
	} else {
		// PIN block is already decrypted under PVK or other key
		pinBlockForClearHex = encryptedPinBlockHex
		logDebug(fmt.Sprintf("DC: using PIN block as is: %s", pinBlockForClearHex))
		logDebug(fmt.Sprintf("DC: account number for PIN extraction: %s", accountNum))
	}

	// Extract clear PIN from decrypted PIN block
	pinBlockFormat, err := hsm.GetPinBlockFormatFromThalesCode(formatCode)
	if err != nil {
		logDebug(fmt.Sprintf("DC: invalid pin block format code %s: %v", formatCode, err))

		return nil, errorcodes.Err23
	}

	clearPINString, err = pinblock.DecodePinBlock(pinBlockForClearHex, accountNum, pinBlockFormat)
	if err != nil {
		logDebug(fmt.Sprintf("DC: failed to extract clear PIN: %v", err))

		return nil, errorcodes.Err20
	}
	logDebug(fmt.Sprintf("DC: clear PIN length: %d", len(clearPINString)))
	logDebug(fmt.Sprintf("DC: account number used: %s", accountNum))
	logDebug(fmt.Sprintf("DC: PVKI used: %s", pvki))

	// Calculate PVV using clear PIN
	calculatedPVV, err := cryptoutils.GetVisaPVV(
		accountNum,
		pvki,
		clearPINString,
		decryptedPVK,
	)
	if err != nil {
		logDebug(fmt.Sprintf("DC: failed to calculate PVV: %v", err))

		return nil, errorcodes.Err68
	}
	logDebug(fmt.Sprintf("DC: calculated PVV: %s", string(calculatedPVV)))
	logDebug(fmt.Sprintf("DC: received PVV: %s", pvv))

	// Validate calculated PVV against received PVV
	if string(calculatedPVV) != pvv {
		logDebug("DC: PVV verification failed")

		return nil, errorcodes.Err01
	}

	logDebug("DC: PIN successfully validated.")

	response := "DD" + errorcodes.Err00.CodeOnly()

	return []byte(response), nil
}
