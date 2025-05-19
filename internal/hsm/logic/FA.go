package logic

import (
	"crypto/des"
	"encoding/hex"
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteFA translates a ZPK from ZMK to LMK (Variant LMK, not keyblock).
func ExecuteFA(input []byte) ([]byte, error) {
	logInfo("FA: starting ZPK translation from ZMK to LMK")
	data := input

	// Parse ZMK (encrypted under LMK)
	var zmkScheme byte = 'U'
	var zmkHex string
	var zmkLen int

	if len(data) < 1 {
		logError("FA: missing ZMK data")
		return nil, errorcodes.Err15
	}

	logInfo("FA: processing ZMK input")
	if data[0] == 'U' || data[0] == 'T' {
		zmkScheme = data[0]
		zmkLen = getKeyLength(zmkScheme)
		if len(data) < 1+zmkLen*2 {
			logError("FA: insufficient data for ZMK with scheme")
			return nil, errorcodes.Err15
		}
		zmkHex = string(data[1 : 1+zmkLen*2])
		data = data[1+zmkLen*2:]
	} else {
		// assume double-length key hex without scheme
		zmkLen = 16 // bytes
		if len(data) < zmkLen*2 {
			logError("FA: insufficient data for ZMK without scheme")
			return nil, errorcodes.Err15
		}
		zmkHex = string(data[:zmkLen*2])
		data = data[zmkLen*2:]
	}

	logInfo("FA: decoding ZMK")
	zmkBytes, err := hex.DecodeString(zmkHex)
	if err != nil {
		logError("FA: invalid ZMK hex format")
		return nil, errorcodes.Err15
	}
	logDebug(fmt.Sprintf("FA: encrypted ZMK value: %x", zmkBytes))

	// Parse ZPK (encrypted under ZMK)
	var zpkScheme byte = 'U'
	var zpkHex string
	var zpkLen int

	if len(data) < 1 {
		logError("FA: missing ZPK data")
		return nil, errorcodes.Err15
	}

	logInfo("FA: processing ZPK input")
	if data[0] == 'U' || data[0] == 'T' {
		zpkScheme = data[0]
		zpkLen = getKeyLength(zpkScheme)
		if len(data) < 1+zpkLen*2 {
			logError("FA: insufficient data for ZPK with scheme")
			return nil, errorcodes.Err15
		}
		zpkHex = string(data[1 : 1+zpkLen*2])
		_ = data[1+zpkLen*2:]
	} else {
		// assume double-length ZPK without scheme
		zpkLen = 16
		if len(data) < zpkLen*2 {
			logError("FA: insufficient data for ZPK without scheme")
			return nil, errorcodes.Err15
		}
		zpkHex = string(data[:zpkLen*2])
	}

	logInfo("FA: decoding ZPK")
	zpkBytes, err := hex.DecodeString(zpkHex)
	if err != nil {
		logError("FA: invalid ZPK hex format")
		return nil, errorcodes.Err15
	}
	logDebug(fmt.Sprintf("FA: encrypted ZPK value: %x", zpkBytes))

	// Decrypt ZMK under LMK (pair 04-05, key type 000)
	logInfo("FA: decrypting ZMK under LMK")
	clearZmk, err := decryptUnderLMK(zmkBytes, "000", zmkScheme)
	if err != nil {
		logError("FA: ZMK decryption failed")
		return nil, errorcodes.Err68
	}

	logInfo("FA: verifying ZMK parity")
	if !cryptoutils.CheckKeyParity(clearZmk) {
		logError("FA: ZMK parity check failed")
		return nil, errorcodes.Err10
	}

	// Decrypt ZPK under ZMK using triple DES
	logInfo("FA: decrypting ZPK under ZMK")
	block, err := des.NewTripleDESCipher(prepareTripleDESKey(clearZmk))
	if err != nil {
		logError("FA: failed to create DES cipher for ZPK")
		return nil, errorcodes.Err15
	}

	clearZpk := make([]byte, len(zpkBytes))
	for i := 0; i < len(zpkBytes); i += 8 {
		block.Decrypt(clearZpk[i:i+8], zpkBytes[i:i+8])
	}
	logDebug(fmt.Sprintf("FA: decrypted ZPK value: %x", clearZpk))

	// Check for all-zero ZPK
	allZero := true
	for _, b := range clearZpk {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		logError("FA: all zero ZPK detected")
		return nil, errorcodes.Err11
	}

	// Check ZPK parity (advice only)
	zpkParityError := false
	logInfo("FA: checking ZPK parity")
	if !cryptoutils.CheckKeyParity(clearZpk) {
		logInfo("FA: fixing ZPK parity")
		zpkParityError = true
		clearZpk = cryptoutils.FixKeyParity(clearZpk)
	}

	// Encrypt ZPK under LMK (pair 06-07, key type 001)
	logInfo("FA: encrypting ZPK under LMK")
	lmkScheme := zpkScheme // Use same scheme as input unless overridden
	lmkEncryptedZpk, err := encryptUnderLMK(clearZpk, "001", lmkScheme)
	if err != nil {
		logError("FA: ZPK encryption under LMK failed")
		return nil, errorcodes.Err68
	}

	// Calculate KCV (6 hex digits, as per spec default)
	logInfo("FA: calculating key check value")
	kcv, err := cryptoutils.KeyCV(cryptoutils.Raw2B(clearZpk), 6)
	if err != nil {
		logError("FA: KCV calculation failed")
		return nil, errorcodes.Err20
	}

	logInfo("FA: formatting response")
	resp := []byte("FB")
	if zpkParityError {
		resp = append(resp, []byte("01")...)
	} else {
		resp = append(resp, []byte("00")...)
	}
	resp = appendEncryptedKeyToResponse(resp, lmkScheme, lmkEncryptedZpk)
	resp = append(resp, kcv...)

	logDebug(fmt.Sprintf("FA: response value: %x", resp))

	return resp, nil
}
