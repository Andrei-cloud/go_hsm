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
	data := input
	logDebug(fmt.Sprintf("FA: input: %x", data))

	// Parse ZMK (encrypted under LMK)
	var zmkScheme byte = 'U'
	var zmkHex string
	var zmkLen int
	if len(data) < 1 {
		logDebug("FA: missing ZMK data.")
		return nil, errorcodes.Err15
	}
	if data[0] == 'U' || data[0] == 'T' {
		zmkScheme = data[0]
		zmkLen = getKeyLength(zmkScheme)
		if len(data) < 1+zmkLen*2 {
			logDebug("FA: insufficient data for ZMK.")
			return nil, errorcodes.Err15
		}
		zmkHex = string(data[1 : 1+zmkLen*2])
		data = data[1+zmkLen*2:]
	} else {
		// assume double-length key hex without scheme
		zmkLen = 16 // bytes
		if len(data) < zmkLen*2 {
			logDebug("FA: insufficient data for ZMK without scheme.")
			return nil, errorcodes.Err15
		}
		zmkHex = string(data[:zmkLen*2])
		data = data[zmkLen*2:]
	}
	zmkBytes, err := hex.DecodeString(zmkHex)
	if err != nil {
		logDebug("FA: failed to decode ZMK hex.")
		return nil, errorcodes.Err15
	}
	logDebug(fmt.Sprintf("FA: ZMK: %x", zmkBytes))

	// Parse ZPK (encrypted under ZMK)
	var zpkScheme byte = 'U'
	var zpkHex string
	var zpkLen int
	if len(data) < 1 {
		logDebug("FA: missing ZPK data.")
		return nil, errorcodes.Err15
	}
	if data[0] == 'U' || data[0] == 'T' {
		zpkScheme = data[0]
		zpkLen = getKeyLength(zpkScheme)
		if len(data) < 1+zpkLen*2 {
			logDebug("FA: insufficient data for ZPK.")
			return nil, errorcodes.Err15
		}
		zpkHex = string(data[1 : 1+zpkLen*2])
		data = data[1+zpkLen*2:]
	} else {
		// assume double-length ZPK without scheme
		zpkLen = 16
		if len(data) < zpkLen*2 {
			logDebug("FA: insufficient data for ZPK without scheme.")
			return nil, errorcodes.Err15
		}
		zpkHex = string(data[:zpkLen*2])
		data = data[zpkLen*2:]
	}
	zpkBytes, err := hex.DecodeString(zpkHex)
	if err != nil {
		logDebug("FA: failed to decode ZPK hex.")
		return nil, errorcodes.Err15
	}
	logDebug(fmt.Sprintf("FA: ZPK: %x", zpkBytes))

	// Decrypt ZMK under LMK (pair 04-05, key type 000)
	clearZmk, err := decryptUnderLMK(zmkBytes, "000", zmkScheme)
	if err != nil {
		logDebug("FA: failed to decrypt ZMK under LMK.")
		return nil, errorcodes.Err68
	}
	if !cryptoutils.CheckKeyParity(clearZmk) {
		logDebug("FA: ZMK parity error.")
		return nil, errorcodes.Err10
	}

	// Decrypt ZPK under ZMK
	// Decrypt ZPK under ZMK using triple DES
	block, err := des.NewTripleDESCipher(prepareTripleDESKey(clearZmk))
	if err != nil {
		logDebug("FA: failed to create DES cipher for ZPK decryption.")
		return nil, errorcodes.Err15
	}
	clearZpk := make([]byte, len(zpkBytes))
	for i := 0; i < len(zpkBytes); i += 8 {
		block.Decrypt(clearZpk[i:i+8], zpkBytes[i:i+8])
	}

	// Check for all-zero ZPK
	allZero := true
	for _, b := range clearZpk {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		logDebug("FA: all zero ZPK.")
		return nil, errorcodes.Err11
	}

	// Check ZPK parity (advice only)
	zpkParityError := false
	if !cryptoutils.CheckKeyParity(clearZpk) {
		logDebug("FA: ZPK parity error (advice only).")
		zpkParityError = true
		// Fix parity using cryptoutils.FixKeyParity
		clearZpk = cryptoutils.FixKeyParity(clearZpk)
	}

	// Encrypt ZPK under LMK (pair 06-07, key type 001)
	lmkScheme := zpkScheme // Use same scheme as input unless overridden by optional field
	lmkEncryptedZpk, err := encryptUnderLMK(clearZpk, "001", lmkScheme)
	if err != nil {
		logDebug("FA: failed to encrypt ZPK under LMK.")
		return nil, errorcodes.Err68
	}

	// Calculate KCV (6 hex digits, as per spec default)
	// KCV uses hex-encoded clear key
	kcv, err := cryptoutils.KeyCV(cryptoutils.Raw2B(clearZpk), 6)
	if err != nil {
		logDebug("FA: failed to calculate KCV.")
		return nil, errorcodes.Err20
	}

	// Build response
	resp := []byte("FB")
	if zpkParityError {
		resp = append(resp, []byte("01")...)
	} else {
		resp = append(resp, []byte("00")...)
	}
	resp = appendEncryptedKeyToResponse(resp, lmkScheme, lmkEncryptedZpk)
	resp = append(resp, kcv...)
	logDebug(fmt.Sprintf("FA: response: %x", resp))
	return resp, nil
}
