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
	data := input
	logDebug(fmt.Sprintf("EC: processing input of length %d: %x", len(data), data))

	// parse ZPK under LMK variant
	if len(data) < 1 {
		logDebug("EC: missing zpk scheme")
		return nil, errorcodes.Err15
	}
	zpkScheme := data[0]
	logDebug(fmt.Sprintf("EC: ZPK scheme: %c", zpkScheme))
	if zpkScheme != 'U' && zpkScheme != 'T' {
		logDebug(fmt.Sprintf("EC: invalid ZPK scheme: %c", zpkScheme))
		return nil, errorcodes.Err26
	}
	rawZpkLen := getKeyLength(zpkScheme)
	hexZpkLen := rawZpkLen * 2
	logDebug(fmt.Sprintf("EC: expected ZPK length: %d bytes (%d hex chars)", rawZpkLen, hexZpkLen))
	if len(data) < 1+hexZpkLen {
		logDebug("EC: insufficient data for encrypted zpk")
		return nil, errorcodes.Err15
	}
	encryptedZpkHex := string(data[1 : 1+hexZpkLen])
	logDebug(fmt.Sprintf("EC: encrypted ZPK hex: %s", encryptedZpkHex))
	data = data[1+hexZpkLen:]
	logDebug(
		fmt.Sprintf("EC: after ZPK, first byte of remaining data: %c (hex %x)", data[0], data[0]),
	)
	encryptedZpk, err := hex.DecodeString(encryptedZpkHex)
	if err != nil {
		logDebug(fmt.Sprintf("EC: failed to decode encrypted ZPK hex: %v", err))
		return nil, errorcodes.Err15
	}
	decryptedZpk, err := decryptUnderLMK(encryptedZpk, "001", zpkScheme)
	if err != nil {
		logDebug(fmt.Sprintf("EC: failed to decrypt ZPK: %v", err))
		return nil, errorcodes.Err68
	}
	logDebug(fmt.Sprintf("EC: decrypted ZPK: %x", decryptedZpk))
	if !cryptoutils.CheckKeyParity(decryptedZpk) {
		logDebug("EC: zpk parity error")
		return nil, errorcodes.Err10
	}

	// parse PVK under LMK variant
	// PVK can be either:
	// 1. 32 hex chars (no scheme) - a pair of single length keys
	// 2. 'U' + 32 hex chars - a double length key with scheme
	var encryptedPvkHex string
	var pvkScheme byte = 'U' // default scheme for double length key

	if data[0] == 'U' {
		// Format 2: Scheme + 32 hex chars
		logDebug("EC: PVK format with scheme U")
		if len(data) < 1+32 {
			logDebug("EC: insufficient data for PVK with scheme")
			return nil, errorcodes.Err15
		}
		encryptedPvkHex = string(data[1:33])
		data = data[33:]
	} else {
		// Format 1: Just 32 hex chars
		logDebug("EC: PVK format without scheme")
		if len(data) < 32 {
			logDebug("EC: insufficient data for PVK without scheme")
			return nil, errorcodes.Err15
		}
		encryptedPvkHex = string(data[:32])
		data = data[32:]
	}

	logDebug(fmt.Sprintf("EC: encrypted PVK hex: %s", encryptedPvkHex))
	encryptedPvk, err := hex.DecodeString(encryptedPvkHex)
	if err != nil {
		logDebug(fmt.Sprintf("EC: failed to decode encrypted PVK hex: %v", err))
		return nil, errorcodes.Err15
	}

	decryptedPvk, err := decryptUnderLMK(encryptedPvk, "002", pvkScheme)
	if err != nil {
		logDebug(fmt.Sprintf("EC: failed to decrypt PVK: %v", err))
		return nil, errorcodes.Err68
	}
	logDebug(fmt.Sprintf("EC: decrypted PVK: %x", decryptedPvk))
	if !cryptoutils.CheckKeyParity(decryptedPvk) {
		logDebug("EC: pvk parity error")
		return nil, errorcodes.Err11
	}

	// parse PIN block + format + account + PVKI + PVV
	const pinHexLen = 16
	const fmtLen = 2
	const accLen = 12
	const pvkiLen = 1
	const pvvLen = 4
	if len(data) < pinHexLen+fmtLen+accLen+pvkiLen+pvvLen {
		logDebug("EC: insufficient data for remaining fields")
		logDebug(fmt.Sprintf("EC: have %d bytes, need %d + %d + %d + %d + %d = %d",
			len(data), pinHexLen, fmtLen, accLen, pvkiLen, pvvLen,
			pinHexLen+fmtLen+accLen+pvkiLen+pvvLen))
		logDebug(fmt.Sprintf("EC: remaining data: %s", data))
		return nil, errorcodes.Err15
	}

	pinHex := string(data[:pinHexLen])
	logDebug(fmt.Sprintf("EC: PIN block hex: %s", pinHex))
	data = data[pinHexLen:]
	formatCode := string(data[:fmtLen])
	data = data[fmtLen:]
	accountNum := string(data[:accLen])
	data = data[accLen:]
	pvki := string(data[:pvkiLen])
	data = data[pvkiLen:]
	pvv := string(data[:pvvLen])

	logDebug(fmt.Sprintf("EC: PIN block: %s", pinHex))
	logDebug(fmt.Sprintf("EC: format code: %s", formatCode))
	logDebug(fmt.Sprintf("EC: account number: %s", accountNum))
	logDebug(fmt.Sprintf("EC: PVKI: %s", pvki))
	logDebug(fmt.Sprintf("EC: PVV: %s", pvv))

	// decrypt PIN block with ZPK
	cipher, err := des.NewTripleDESCipher(prepareTripleDESKey(decryptedZpk))
	if err != nil {
		logDebug(fmt.Sprintf("EC: failed to create ZPK cipher: %v", err))
		return nil, fmt.Errorf("create zpk cipher: %w", err)
	}
	encPin, err := hex.DecodeString(pinHex)
	if err != nil {
		logDebug(fmt.Sprintf("EC: failed to decode PIN block hex: %v", err))
		return nil, errorcodes.Err15
	}
	clearBlock := make([]byte, len(encPin))
	cipher.Decrypt(clearBlock, encPin)
	logDebug(fmt.Sprintf("EC: decrypted PIN block: %x", clearBlock))

	pinFormat, err := hsm.GetPinBlockFormatFromThalesCode(formatCode)
	if err != nil {
		logDebug(fmt.Sprintf("EC: failed to get PIN block format: %v", err))
		return nil, errorcodes.Err23
	}
	clearPIN, err := pinblock.DecodePinBlock(hex.EncodeToString(clearBlock), accountNum, pinFormat)
	if err != nil {
		logDebug(fmt.Sprintf("EC: failed to extract clear PIN: %v", err))
		return nil, errorcodes.Err20
	}
	logDebug(fmt.Sprintf("EC: clear PIN: %s", clearPIN))

	// calculate and verify PVV
	calculated, err := cryptoutils.GetVisaPVV(accountNum, pvki, clearPIN, decryptedPvk)
	if err != nil {
		logDebug(fmt.Sprintf("EC: failed to calculate PVV: %v", err))
		return nil, errorcodes.Err68
	}
	logDebug(fmt.Sprintf("EC: calculated PVV: %s", calculated))
	if string(calculated) != pvv {
		logDebug("EC: pvv verification failed")
		return nil, errorcodes.Err01
	}

	logDebug("EC: pvv verification succeeded")
	return []byte("ED" + errorcodes.Err00.CodeOnly()), nil
}
