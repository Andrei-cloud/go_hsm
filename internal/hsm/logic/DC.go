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
func ExecuteDC(
	input []byte,
	decryptUnderLMK func([]byte) ([]byte, error),
	_ func([]byte) ([]byte, error), // Placeholder for encryptUnderLMK, unused in DC.
	logFn func(string),
) ([]byte, error) {
	data := input
	// Minimum length calculation:
	// TPK (48 for 24-byte key) + PIN Block (16) + Source PIN Block Format (2) +
	// Account Number (12) + PVKI (2) + PVV (8) = 88 bytes.
	if len(data) < 88 {
		logFn(fmt.Sprintf("DC: insufficient data length, expected at least 88, got %d", len(data)))

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
			logFn(fmt.Sprintf("DC: invalid TPK hex format: %v", err))

			return nil, errorcodes.Err15
		}
		data = data[tpkSize:]

		// Decrypt and validate TPK
		decryptedTPK, err = decryptUnderLMK(tpkRaw)
		if err != nil {
			logFn(fmt.Sprintf("DC: failed to decrypt TPK: %v", err))

			return nil, errorcodes.Err68
		}

		if !cryptoutils.CheckKeyParity(decryptedTPK) {
			logFn("DC: decrypted TPK parity error")

			return nil, errorcodes.Err10
		}
	}

	// Handle PVK extraction and validation
	if len(data) < pvkDoubleSize+1 { // Need 1 for scheme + 32 for hex key
		logFn("DC: insufficient data for PVK")

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
			logFn(fmt.Sprintf("DC: invalid PVK hex format: %v", err))

			return nil, errorcodes.Err15
		}

		// Decrypt PVK first
		decryptedPVK, err = decryptUnderLMK(rawPvk)
		if err != nil {
			logFn(fmt.Sprintf("DC: failed to decrypt PVK: %v", err))

			return nil, errorcodes.Err68
		}

		// Check parity after decryption
		if !cryptoutils.CheckKeyParity(decryptedPVK) {
			logFn("DC: decrypted PVK parity error")

			return nil, errorcodes.Err11
		}
		pvkBytesToSkip = 1 + pvkDoubleSize // Skip scheme + hex key
	} else {
		// Single length key pair - process PVK A and PVK B
		// Ensure enough data for two single keys
		if len(data) < pvkDoubleSize { // Need 16 + 16 hex chars
			logFn("DC: insufficient data for PVK pair")

			return nil, errorcodes.Err15
		}

		encpvkAB, err := hex.DecodeString(string(data[:pvkDoubleSize]))
		if err != nil {
			logFn(fmt.Sprintf("DC: invalid PVK pair hex format: %v", err))

			return nil, errorcodes.Err15
		}

		// Decrypt extended PVK A + B
		decryptedPVKAB, err := decryptUnderLMK(encpvkAB)
		if err != nil {
			logFn(fmt.Sprintf("DC: failed to decrypt PVK A: %v", err))

			return nil, errorcodes.Err68
		}

		// Check PVK A parity after decryption
		if !cryptoutils.CheckKeyParity(decryptedPVKAB[:pvkSingleSize/2]) {
			logFn("DC: decrypted PVK A parity error")

			return nil, errorcodes.Err11
		}

		// Check PVK B parity after decryption
		if !cryptoutils.CheckKeyParity(decryptedPVKAB[pvkSingleSize/2 : pvkDoubleSize/2]) {
			logFn("DC: decrypted PVK B parity error")

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
		logFn("DC: insufficient data for remaining fields")

		return nil, errorcodes.Err15
	}

	// Extract encrypted PIN block
	encryptedPinBlockHex := string(data[:pinBlockSize])
	data = data[pinBlockSize:]
	logFn(fmt.Sprintf("DC: parsed encrypted PIN block: %s", encryptedPinBlockHex))

	// Skip format code
	formatCode := string(data[:fmtCodeSize])
	data = data[fmtCodeSize:]
	logFn(fmt.Sprintf("DC: parsed format code: %s", formatCode))

	accountNum := string(data[:accNumSize])
	data = data[accNumSize:]
	logFn(fmt.Sprintf("DC: parsed account number: %s", accountNum))

	pvki := string(data[:pvkiSize])
	data = data[pvkiSize:]
	logFn(fmt.Sprintf("DC: parsed PVKI: %s", pvki))

	pvv := string(data[:pvvSize])
	logFn(fmt.Sprintf("DC: parsed PVV: %s", pvv))

	// If TPK was present, decrypt the PIN block using TPK
	var pinBlockForClearHex string
	if decryptedTPK != nil {
		logFn(fmt.Sprintf("DC: processing with TPK present, TPK length: %d", len(decryptedTPK)))
		// Create TPK cipher
		var fullTPK []byte
		switch {
		case firstByte == 'U':
			// Double length key - use as is
			fullTPK = make([]byte, 24)
			copy(fullTPK, decryptedTPK)
			copy(fullTPK[16:], decryptedTPK[:8])
			logFn("DC: using double-length TPK with U schema")
		case len(decryptedTPK) == 16:
			// Single length key
			fullTPK = make([]byte, 24)
			copy(fullTPK, decryptedTPK)
			copy(fullTPK[8:], decryptedTPK[:8])
			copy(fullTPK[16:], decryptedTPK[:8])
			logFn("DC: extended single-length TPK to triple-length")
		default:
			fullTPK = decryptedTPK
			logFn("DC: using double/triple-length TPK as is")
		}

		// Create TPK cipher
		tpkCipher, err := des.NewTripleDESCipher(fullTPK)
		if err != nil {
			logFn(fmt.Sprintf("DC: failed to create TPK cipher: %v", err))

			return nil, errorcodes.Err68
		}

		// Convert PIN block from hex to binary
		pinBlockBin, err := hex.DecodeString(encryptedPinBlockHex)
		if err != nil {
			logFn(fmt.Sprintf("DC: invalid PIN block hex format: %v", err))

			return nil, errorcodes.Err15
		}
		logFn(fmt.Sprintf("DC: decoded PIN block binary length: %d", len(pinBlockBin)))

		// Decrypt PIN block using TPK
		decryptedPinBlock := make([]byte, len(pinBlockBin))
		tpkCipher.Decrypt(decryptedPinBlock, pinBlockBin)
		pinBlockForClearHex = hex.EncodeToString(decryptedPinBlock)
		logFn(fmt.Sprintf("DC: decrypted PIN block hex: %s", pinBlockForClearHex))
		logFn(fmt.Sprintf("DC: account number for PIN extraction: %s", accountNum))
	} else {
		pinBlockForClearHex = encryptedPinBlockHex
		logFn(fmt.Sprintf("DC: using encrypted PIN block as is: %s", pinBlockForClearHex))
		logFn(fmt.Sprintf("DC: account number for PIN extraction: %s", accountNum))
	}

	// Extract clear PIN from decrypted PIN block
	pinBlockFormat, err := hsm.GetPinBlockFormatFromThalesCode(formatCode)
	if err != nil {
		logFn(fmt.Sprintf("DC: invalid pin block format code %s: %v", formatCode, err))

		return nil, errorcodes.Err23
	}

	clearPINString, err = pinblock.DecodePinBlock(pinBlockForClearHex, accountNum, pinBlockFormat)
	if err != nil {
		logFn(fmt.Sprintf("DC: failed to extract clear PIN: %v", err))

		return nil, errorcodes.Err20
	}
	logFn(fmt.Sprintf("DC: clear PIN length: %d", len(clearPINString)))
	logFn(fmt.Sprintf("DC: account number used: %s", accountNum))
	logFn(fmt.Sprintf("DC: PVKI used: %s", pvki))

	// Calculate PVV using clear PIN
	calculatedPVV, err := cryptoutils.GetVisaPVV(
		accountNum,
		pvki,
		clearPINString,
		decryptedPVK,
	)
	if err != nil {
		logFn(fmt.Sprintf("DC: failed to calculate PVV: %v", err))

		return nil, errorcodes.Err68
	}
	logFn(fmt.Sprintf("DC: calculated PVV: %s", string(calculatedPVV)))
	logFn(fmt.Sprintf("DC: received PVV: %s", pvv))

	// Validate calculated PVV against received PVV
	if string(calculatedPVV) != pvv {
		logFn("DC: PVV verification failed")

		return nil, errorcodes.Err01
	}

	logFn(
		"DC: PIN successfully validated.",
	)

	// Construct response: command code (DD) + error code (00 for successful parsing and PIN extraction)
	// A real implementation would return 00 for successful verification, or an appropriate error code.
	response := "DD" + errorcodes.Err00.CodeOnly()

	return []byte(response), nil
}
