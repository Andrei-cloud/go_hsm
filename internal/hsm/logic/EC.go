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

// ExecuteEC processes the EC (Verify PIN) command and returns response bytes.
// Format: [TPK scheme + key](optional) + PVK + PIN block + format code + account number + PVKI + PVV.
func ExecuteEC(input []byte) ([]byte, error) {
	data := input
	if len(data) < tpkSize {
		logDebug("EC: insufficient data length")

		return nil, errorcodes.Err15
	}

	var clearPINString string
	firstByte := data[0]
	var decryptedTPK []byte

	// Handle optional TPK
	if firstByte == 'U' || firstByte == 'T' || firstByte == 'S' {
		// Extract and decrypt TPK
		tpkRaw, err := hex.DecodeString(string(data[1:tpkSize]))
		if err != nil {
			logDebug(fmt.Sprintf("EC: invalid TPK hex format: %v", err))

			return nil, errorcodes.Err15
		}
		data = data[tpkSize:]

		// Decrypt and validate TPK
		clearTPK, err := decryptUnderLMK(tpkRaw)
		if err != nil {
			logDebug(fmt.Sprintf("EC: failed to decrypt TPK: %v", err))

			return nil, errorcodes.Err68
		}

		logDebug(fmt.Sprintf("EC: decrypted TPK length: %d", len(decryptedTPK)))
		logDebug(fmt.Sprintf("EC: decrypted TPK hex: %s", cryptoutils.Raw2Str(decryptedTPK)))

		if !cryptoutils.CheckKeyParity(decryptedTPK) {
			logDebug("EC: decrypted TPK parity error")

			return nil, errorcodes.Err10
		}

		decryptedTPK = append(decryptedTPK, clearTPK...)
	}

	// Handle PVK extraction and validation
	if len(data) < pvkDoubleSize+1 { // Need 1 for scheme + 32 for hex key
		logDebug("EC: insufficient data for PVK")

		return nil, errorcodes.Err15
	}

	// Check if PVK starts with schema character
	pvkScheme := data[0]
	var decryptedPVK []byte
	var pvkBytesToSkip int // Track how many bytes to skip after PVK processing

	if pvkScheme == 'U' || pvkScheme == 'T' {
		// Double or triple length key with schema
		pvkData := data[1 : 1+pvkDoubleSize] // Read 32 hex chars after scheme
		rawPvk, err := hex.DecodeString(string(pvkData))
		if err != nil {
			logDebug(fmt.Sprintf("EC: invalid PVK hex format: %v", err))

			return nil, errorcodes.Err15
		}

		// Decrypt PVK first
		decryptedPVK, err = decryptUnderLMK(rawPvk)
		if err != nil {
			logDebug(fmt.Sprintf("EC: failed to decrypt PVK: %v", err))

			return nil, errorcodes.Err68
		}

		// Check parity after decryption
		if !cryptoutils.CheckKeyParity(decryptedPVK) {
			logDebug("EC: decrypted PVK parity error")

			return nil, errorcodes.Err11
		}
		pvkBytesToSkip = 1 + pvkDoubleSize // Skip scheme + hex key
	} else {
		// Single length key pair - process PVK A and PVK B
		// Ensure enough data for two single keys
		if len(data) < pvkDoubleSize { // Need 16 + 16 hex chars
			logDebug("EC: insufficient data for PVK pair")

			return nil, errorcodes.Err15
		}

		encpvkAB, err := hex.DecodeString(string(data[:pvkDoubleSize]))
		if err != nil {
			logDebug(fmt.Sprintf("EC: invalid PVK pair hex format: %v", err))

			return nil, errorcodes.Err15
		}

		// Decrypt extended PVK A + B
		decryptedPVKAB, err := decryptUnderLMK(encpvkAB)
		if err != nil {
			logDebug(fmt.Sprintf("EC: failed to decrypt PVK A: %v", err))

			return nil, errorcodes.Err68
		}

		logDebug(fmt.Sprintf("EC: decrypted PVK A + B length: %d", len(decryptedPVKAB)))
		logDebug(fmt.Sprintf("EC: decrypted PVK A + B hex: %s", cryptoutils.Raw2Str(decryptedPVKAB)))

		// Check PVK A parity after decryption
		if !cryptoutils.CheckKeyParity(decryptedPVKAB[:pvkSingleSize/2]) {
			logDebug("EC: decrypted PVK A parity error")

			return nil, errorcodes.Err11
		}

		// Check PVK B parity after decryption
		if !cryptoutils.CheckKeyParity(decryptedPVKAB[pvkSingleSize/2 : pvkDoubleSize/2]) {
			logDebug("EC: decrypted PVK B parity error")

			return nil, errorcodes.Err11
		}

		// Combine PVK A and PVK B for final PVK (16 raw bytes)
		decryptedPVK = decryptedPVKAB
		pvkBytesToSkip = pvkDoubleSize // Skip the two hex keys (16+16).
	}

	// Move to the next field after PVK
	data = data[pvkBytesToSkip:]

	// Extract and validate remaining fields
	if len(data) < pinBlockSize+fmtCodeSize+accNumSize+pvkiSize+pvvSize {
		logDebug("EC: insufficient data for remaining fields")

		return nil, errorcodes.Err15
	}

	// Extract encrypted PIN block
	encryptedPinBlockHex := string(data[:pinBlockSize])
	data = data[pinBlockSize:]
	logDebug(fmt.Sprintf("EC: parsed encrypted PIN block: %s", encryptedPinBlockHex))

	// Skip format code
	formatCode := string(data[:fmtCodeSize])
	data = data[fmtCodeSize:]
	logDebug(fmt.Sprintf("EC: parsed format code: %s", formatCode))

	accountNum := string(data[:accNumSize])
	data = data[accNumSize:]
	logDebug(fmt.Sprintf("EC: parsed account number: %s", accountNum))

	pvki := string(data[:pvkiSize])
	data = data[pvkiSize:]
	logDebug(fmt.Sprintf("EC: parsed PVKI: %s", pvki))

	pvv := string(data[:pvvSize])
	logDebug(fmt.Sprintf("EC: parsed PVV: %s", pvv))

	// If TPK was present, decrypt the PIN block using TPK
	var pinBlockForClearHex string
	if decryptedTPK != nil {
		logDebug(fmt.Sprintf("EC: processing with TPK present, TPK length: %d", len(decryptedTPK)))
		// Create TPK cipher
		var fullTPK []byte
		switch {
		case firstByte == 'U':
			// Double length key - use as is
			fullTPK = make([]byte, 24)
			copy(fullTPK, decryptedTPK)
			copy(fullTPK[16:], decryptedTPK[:8])
			logDebug("EC: using double-length TPK with U schema")
		case len(decryptedTPK) == 16:
			// Single length key
			fullTPK = make([]byte, 24)
			copy(fullTPK, decryptedTPK)
			copy(fullTPK[8:], decryptedTPK[:8])
			copy(fullTPK[16:], decryptedTPK[:8])
			logDebug("EC: extended single-length TPK to triple-length")
		default:
			fullTPK = decryptedTPK
			logDebug("EC: using double/triple-length TPK as is")
		}

		// Create TPK cipher
		tpkCipher, err := des.NewTripleDESCipher(fullTPK)
		if err != nil {
			logDebug(fmt.Sprintf("EC: failed to create TPK cipher: %v", err))

			return nil, errorcodes.Err68
		}

		// Convert PIN block from hex to binary
		pinBlockBin, err := hex.DecodeString(encryptedPinBlockHex)
		if err != nil {
			logDebug(fmt.Sprintf("EC: invalid PIN block hex format: %v", err))

			return nil, errorcodes.Err15
		}
		logDebug(fmt.Sprintf("EC: decoded PIN block binary length: %d", len(pinBlockBin)))

		// Decrypt PIN block using TPK
		decryptedPinBlock := make([]byte, len(pinBlockBin))
		tpkCipher.Decrypt(decryptedPinBlock, pinBlockBin)
		pinBlockForClearHex = hex.EncodeToString(decryptedPinBlock)
		logDebug(fmt.Sprintf("EC: decrypted PIN block hex: %s", pinBlockForClearHex))
		logDebug(fmt.Sprintf("EC: account number for PIN extraction: %s", accountNum))
	} else {
		pinBlockForClearHex = encryptedPinBlockHex
		logDebug(fmt.Sprintf("EC: using encrypted PIN block as is: %s", pinBlockForClearHex))
		logDebug(fmt.Sprintf("EC: account number for PIN extraction: %s", accountNum))
	}

	logDebug(fmt.Sprintf("EC: decrypted PIN block hex: %s", pinBlockForClearHex))
	// Extract clear PIN from decrypted PIN block
	pinBlockFormat, err := hsm.GetPinBlockFormatFromThalesCode(formatCode)
	if err != nil {
		logDebug(fmt.Sprintf("EC: invalid pin block format code %s: %v", formatCode, err))

		return nil, errorcodes.Err23
	}

	clearPINString, err = pinblock.DecodePinBlock(pinBlockForClearHex, accountNum, pinBlockFormat)
	if err != nil {
		logDebug(fmt.Sprintf("EC: failed to extract clear PIN: %v", err))

		return nil, errorcodes.Err20
	}
	logDebug(fmt.Sprintf("EC: clear PIN length: %d", len(clearPINString)))
	logDebug(fmt.Sprintf("EC: account number used: %s", accountNum))
	logDebug(fmt.Sprintf("EC: PVKI used: %s", pvki))

	// Calculate PVV using clear PIN
	calculatedPVV, err := cryptoutils.GetVisaPVV(
		accountNum,
		pvki,
		clearPINString,
		decryptedPVK,
	)
	if err != nil {
		logDebug(fmt.Sprintf("EC: failed to calculate PVV: %v", err))

		return nil, errorcodes.Err68
	}
	logDebug(fmt.Sprintf("EC: calculated PVV: %s", string(calculatedPVV)))
	logDebug(fmt.Sprintf("EC: received PVV: %s", pvv))

	// Validate calculated PVV against received PVV
	if string(calculatedPVV) != pvv {
		logDebug("EC: PVV verification failed")

		return nil, errorcodes.Err01
	}

	logDebug("EC: PIN verified successfully")

	return []byte("ED" + errorcodes.Err00.CodeOnly()), nil
}
