package logic

import (
	"crypto/des"
	"encoding/hex"
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
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
// Format: [TPK scheme + key](optional) + PVK + PIN block + format code + account number + PVKI + PVV.
func ExecuteDC(
	input []byte,
	decryptUnderLMK func([]byte) ([]byte, error),
	_ func([]byte) ([]byte, error), // Placeholder for encryptUnderLMK, unused in DC.
	logFn func(string),
) ([]byte, error) {
	data := input
	if len(data) < tpkSize {
		logFn("DC: insufficient data length")

		return nil, errorcodes.Err15
	}

	var clearPIN []byte
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
	encryptedPinBlock := data[:pinBlockSize]
	data = data[pinBlockSize:]
	logFn(fmt.Sprintf("DC: parsed encrypted PIN block: %s", string(encryptedPinBlock)))

	// Skip format code
	formatCode := data[:fmtCodeSize]
	data = data[fmtCodeSize:]
	logFn(fmt.Sprintf("DC: parsed format code: %s", string(formatCode)))

	accountNum := data[:accNumSize]
	data = data[accNumSize:]
	logFn(fmt.Sprintf("DC: parsed account number: %s", string(accountNum)))

	pvki := data[:pvkiSize]
	data = data[pvkiSize:]
	logFn(fmt.Sprintf("DC: parsed PVKI: %s", string(pvki)))

	pvv := data[:pvvSize]
	logFn(fmt.Sprintf("DC: parsed PVV: %s", string(pvv)))

	// If TPK was present, decrypt the PIN block using TPK
	var pinBlockForClear []byte
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
		pinBlockBin, err := hex.DecodeString(string(encryptedPinBlock))
		if err != nil {
			logFn(fmt.Sprintf("DC: invalid PIN block hex format: %v", err))

			return nil, errorcodes.Err15
		}
		logFn(fmt.Sprintf("DC: decoded PIN block binary length: %d", len(pinBlockBin)))

		// Decrypt PIN block using TPK
		decryptedPinBlock := make([]byte, len(pinBlockBin))
		tpkCipher.Decrypt(decryptedPinBlock, pinBlockBin)
		pinBlockForClear = []byte(cryptoutils.Raw2Str(decryptedPinBlock))
		logFn(fmt.Sprintf("DC: decrypted PIN block length: %d", len(pinBlockForClear)))
		logFn(fmt.Sprintf("DC: decrypted PIN block hex: %s", string(pinBlockForClear)))
		logFn(fmt.Sprintf("DC: account number for PIN extraction: %s", string(accountNum)))
	} else {
		pinBlockForClear = encryptedPinBlock
		logFn(fmt.Sprintf("DC: using encrypted PIN block as is: %s", string(pinBlockForClear)))
		logFn(fmt.Sprintf("DC: account number for PIN extraction: %s", string(accountNum)))
	}

	// Extract clear PIN from decrypted PIN block
	// Use the injected getClearPin function.
	clearPIN, err := cryptoutils.GetClearPin(
		pinBlockForClear,
		string(accountNum),
	)
	if err != nil {
		logFn(fmt.Sprintf("DC: failed to extract clear PIN: %v", err))

		return nil, errorcodes.Err20
	}
	logFn(fmt.Sprintf("DC: clear PIN length: %d", len(clearPIN)))
	logFn(fmt.Sprintf("DC: account number used: %s", string(accountNum)))
	logFn(fmt.Sprintf("DC: PVKI used: %s", string(pvki)))

	// Calculate PVV using clear PIN
	// Use the injected getVisaPVV function.
	calculatedPVV, err := cryptoutils.GetVisaPVV(
		string(accountNum),
		string(pvki),
		string(clearPIN),
		decryptedPVK,
	)
	if err != nil {
		logFn(fmt.Sprintf("DC: failed to calculate PVV: %v", err))

		return nil, errorcodes.Err68
	}
	logFn(fmt.Sprintf("DC: calculated PVV: %s", string(calculatedPVV)))
	logFn(fmt.Sprintf("DC: received PVV: %s", string(pvv)))

	// Validate calculated PVV against received PVV
	if string(calculatedPVV) != string(pvv) {
		logFn("DC: PVV verification failed")

		return nil, errorcodes.Err01
	}

	logFn("DC: PIN verified successfully")

	return []byte("DD" + errorcodes.Err00.CodeOnly()), nil
}
