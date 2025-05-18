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
// Format: [ZPK scheme + key] + PVK scheme + key + PIN block + format code + account number + PVKI + PVV.
func ExecuteEC(input []byte) ([]byte, error) {
	logInfo("EC: starting PIN verification using ABA PVV")
	data := input

	// Parse ZPK under LMK variant
	if len(data) < 1 {
		logError("EC: missing ZPK scheme")
		return nil, errorcodes.Err15
	}

	zpkScheme := data[0]
	logDebug(fmt.Sprintf("EC: ZPK scheme: %c", zpkScheme))
	if zpkScheme != 'U' && zpkScheme != 'T' {
		logError("EC: invalid ZPK scheme value")
		return nil, errorcodes.Err26
	}

	rawZpkLen := getKeyLength(zpkScheme)
	hexZpkLen := rawZpkLen * 2
	logDebug(fmt.Sprintf("EC: ZPK length: %d bytes (%d hex chars)", rawZpkLen, hexZpkLen))

	if len(data) < 1+hexZpkLen {
		logError("EC: insufficient data for ZPK key")
		return nil, errorcodes.Err15
	}

	logInfo("EC: extracting and decrypting ZPK")
	encryptedZpkHex := string(data[1 : 1+hexZpkLen])
	data = data[1+hexZpkLen:]

	encryptedZpk, err := hex.DecodeString(encryptedZpkHex)
	if err != nil {
		logError("EC: invalid ZPK hex format")
		return nil, errorcodes.Err15
	}

	decryptedZpk, err := decryptUnderLMK(encryptedZpk, "001", zpkScheme)
	if err != nil {
		logError("EC: ZPK decryption failed")
		return nil, errorcodes.Err68
	}

	logInfo("EC: verifying ZPK parity")
	if !cryptoutils.CheckKeyParity(decryptedZpk) {
		logError("EC: ZPK parity check failed")
		return nil, errorcodes.Err10
	}

	// Parse PVK under LMK variant
	// PVK can be either:
	// 1. 32 hex chars (no scheme) - a pair of single length keys, each encrypted separately
	// 2. 'U' + 32 hex chars - a double length key with scheme
	var encryptedPvkHex string
	var pvkScheme byte = 'U' // default scheme for double length key
	const singleKeySize = 16 // 8 bytes = 16 hex chars
	var decryptedPvk []byte

	if data[0] == 'U' {
		logInfo("EC: processing double-length PVK with scheme")
		if len(data) < 1+32 {
			logError("EC: insufficient data for PVK with scheme")
			return nil, errorcodes.Err15
		}
		encryptedPvkHex = string(data[1:33])
		data = data[33:]

		// Decrypt as one double-length key
		encryptedPvk, err := hex.DecodeString(encryptedPvkHex)
		if err != nil {
			logError("EC: invalid PVK hex format")
			return nil, errorcodes.Err15
		}

		logInfo("EC: decrypting PVK under LMK")
		decryptedPvk, err = decryptUnderLMK(encryptedPvk, "002", pvkScheme)
		if err != nil {
			logError("EC: PVK decryption failed")
			return nil, errorcodes.Err68
		}
	} else {
		logInfo("EC: processing PVK as two single-length components")
		if len(data) < 32 {
			logError("EC: insufficient data for PVK components")
			return nil, errorcodes.Err15
		}
		encryptedPvkHex = string(data[:32])
		data = data[32:]

		// Split into two parts and decrypt each separately
		encryptedPvkA := encryptedPvkHex[:singleKeySize]
		encryptedPvkB := encryptedPvkHex[singleKeySize:]

		// Decrypt part A
		logInfo("EC: decrypting first PVK component")
		encPvkBytesA, err := hex.DecodeString(encryptedPvkA)
		if err != nil {
			logError("EC: invalid first PVK component hex format")
			return nil, errorcodes.Err15
		}
		decryptedPvkA, err := decryptUnderLMK(encPvkBytesA, "002", 'X')
		if err != nil {
			logError("EC: first PVK component decryption failed")
			return nil, errorcodes.Err68
		}

		// Decrypt part B
		logInfo("EC: decrypting second PVK component")
		encPvkBytesB, err := hex.DecodeString(encryptedPvkB)
		if err != nil {
			logError("EC: invalid second PVK component hex format")
			return nil, errorcodes.Err15
		}
		decryptedPvkB, err := decryptUnderLMK(encPvkBytesB, "002", 'X')
		if err != nil {
			logError("EC: second PVK component decryption failed")
			return nil, errorcodes.Err68
		}

		// Concatenate the decrypted parts
		decryptedPvk = append(decryptedPvkA, decryptedPvkB...)
	}

	logInfo("EC: verifying PVK components parity")
	// Check parity for each half of the key separately
	pvkA := decryptedPvk[:8]   // First 8 bytes
	pvkB := decryptedPvk[8:16] // Second 8 bytes
	if !cryptoutils.CheckKeyParity(pvkA) {
		logError("EC: first PVK component parity check failed")
		return nil, errorcodes.Err11
	}
	if !cryptoutils.CheckKeyParity(pvkB) {
		logError("EC: second PVK component parity check failed")
		return nil, errorcodes.Err11
	}

	// Parse remaining fields
	const pinHexLen = 16
	const fmtLen = 2
	const accLen = 12
	const pvkiLen = 1
	const pvvLen = 4

	if len(data) < pinHexLen+fmtLen+accLen+pvkiLen+pvvLen {
		logError("EC: insufficient data for remaining fields")
		return nil, errorcodes.Err15
	}

	logInfo("EC: extracting input fields")
	pinHex := string(data[:pinHexLen])
	data = data[pinHexLen:]
	logDebug(fmt.Sprintf("EC: PIN block value: %s", pinHex))

	formatCode := string(data[:fmtLen])
	data = data[fmtLen:]
	logDebug(fmt.Sprintf("EC: format code: %s", formatCode))

	accountNum := string(data[:accLen])
	data = data[accLen:]
	logDebug(fmt.Sprintf("EC: account number: %s", accountNum))

	pvki := string(data[:pvkiLen])
	data = data[pvkiLen:]
	logDebug(fmt.Sprintf("EC: PVKI: %s", pvki))

	pvv := string(data[:pvvLen])
	logDebug(fmt.Sprintf("EC: received PVV: %s", pvv))

	// Decrypt PIN block with ZPK
	logInfo("EC: preparing to decrypt PIN block")
	cipher, err := des.NewTripleDESCipher(prepareTripleDESKey(decryptedZpk))
	if err != nil {
		logError("EC: failed to create ZPK cipher")
		return nil, fmt.Errorf("create zpk cipher: %w", err)
	}

	encPin, err := hex.DecodeString(pinHex)
	if err != nil {
		logError("EC: invalid PIN block hex format")
		return nil, errorcodes.Err15
	}

	logInfo("EC: decrypting PIN block with ZPK")
	clearBlock := make([]byte, len(encPin))
	cipher.Decrypt(clearBlock, encPin)
	logDebug(fmt.Sprintf("EC: decrypted PIN block value: %x", clearBlock))

	logInfo("EC: validating PIN block format")
	pinFormat, err := hsm.GetPinBlockFormatFromThalesCode(formatCode)
	if err != nil {
		logError(fmt.Sprintf("EC: invalid PIN block format code: %s", formatCode))
		return nil, errorcodes.Err23
	}

	logInfo("EC: extracting clear PIN from PIN block")
	clearPIN, err := pinblock.DecodePinBlock(hex.EncodeToString(clearBlock), accountNum, pinFormat)
	if err != nil {
		logError("EC: failed to extract clear PIN")
		return nil, errorcodes.Err20
	}
	logDebug(fmt.Sprintf("EC: extracted PIN length: %d", len(clearPIN)))

	// Calculate and verify PVV
	logInfo("EC: calculating PVV with extracted PIN")
	calculated, err := cryptoutils.GetVisaPVV(accountNum, pvki, clearPIN, decryptedPvk)
	if err != nil {
		logError("EC: failed to calculate PVV")
		return nil, errorcodes.Err68
	}
	logDebug(fmt.Sprintf("EC: calculated PVV value: %s", calculated))

	logInfo("EC: validating calculated PVV against input")
	if string(calculated) != pvv {
		logError("EC: PVV verification failed")
		return nil, errorcodes.Err01
	}

	logInfo("EC: PIN verification completed successfully")
	return []byte("ED" + errorcodes.Err00.CodeOnly()), nil
}
