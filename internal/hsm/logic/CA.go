// filepath: internal/hsm/logic/CA.go
package logic

import (
	"crypto/des"
	"encoding/hex"
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteCA translates a PIN block encrypted under a TPK to one encrypted under a ZPK or BDK under Variant LMK.
func ExecuteCA(input []byte) ([]byte, error) {
	data := input
	logDebug(fmt.Sprintf("CA: input length: %d, hex: %x", len(input), input))

	// Parse source TPK
	srcScheme := data[0]
	logDebug(fmt.Sprintf("CA: srcScheme: %c", srcScheme))
	rawSrc := getKeyLength(srcScheme)
	hexSrc := rawSrc * 2
	if srcScheme != 'U' && srcScheme != 'T' && srcScheme != 'X' {
		logDebug("CA: invalid srcScheme")
		return nil, errorcodes.Err15
	}
	if len(data) < 1+hexSrc {
		logDebug("CA: insufficient data for srcHex")
		return nil, errorcodes.Err15
	}
	srcHex := string(data[1 : 1+hexSrc])
	logDebug(fmt.Sprintf("CA: srcHex: %s", srcHex))
	data = data[1+hexSrc:]
	srcBytes, err := hex.DecodeString(srcHex)
	if err != nil {
		logDebug("CA: failed to decode srcHex")
		return nil, errorcodes.Err15
	}
	srcClear, err := decryptUnderLMK(srcBytes, "002", srcScheme)
	if err != nil {
		logDebug("CA: failed to decrypt srcBytes under LMK")
		return nil, errorcodes.Err68
	}
	logDebug(fmt.Sprintf("CA: srcClear: %x", srcClear))
	if !cryptoutils.CheckKeyParity(srcClear) {
		logDebug("CA: srcClear parity error")
		return nil, errorcodes.Err10
	}

	// Parse optional destination flag
	keyType := "001"
	if data[0] == '*' {
		keyType = "009"
		logDebug("CA: destination flag is * (keyType=009)")
		data = data[1:]
	} else if data[0] == '~' {
		keyType = "609"
		logDebug("CA: destination flag is ~ (keyType=609)")
		data = data[1:]
	}

	// Parse destination key
	dstScheme := data[0]
	logDebug(fmt.Sprintf("CA: dstScheme: %c", dstScheme))
	rawDst := getKeyLength(dstScheme)
	hexDst := rawDst * 2
	if dstScheme != 'U' && dstScheme != 'T' && dstScheme != 'X' {
		logDebug("CA: invalid dstScheme")
		return nil, errorcodes.Err15
	}
	if len(data) < 1+hexDst {
		logDebug("CA: insufficient data for dstHex")
		return nil, errorcodes.Err15
	}
	dstHex := string(data[1 : 1+hexDst])
	logDebug(fmt.Sprintf("CA: dstHex: %s", dstHex))
	data = data[1+hexDst:]
	dstBytes, err := hex.DecodeString(dstHex)
	if err != nil {
		logDebug("CA: failed to decode dstHex")
		return nil, errorcodes.Err15
	}
	dstClear, err := decryptUnderLMK(dstBytes, keyType, dstScheme)
	if err != nil {
		logDebug("CA: failed to decrypt dstBytes under LMK")
		return nil, errorcodes.Err68
	}
	logDebug(fmt.Sprintf("CA: dstClear: %x", dstClear))
	if !cryptoutils.CheckKeyParity(dstClear) {
		logDebug("CA: dstClear parity error")
		return nil, errorcodes.Err11
	}

	pinLen := data[:2]
	logDebug(fmt.Sprintf("CA: pinLen: %s", string(pinLen)))
	data = data[2:]

	// Parse PIN block hex
	pinHex := string(data[:16])
	logDebug(fmt.Sprintf("CA: pinHex: %s", pinHex))
	data = data[16:]

	// Parse source and destination format codes separately
	fmtSrc := string(data[:2])
	fmtDst := string(data[2:4])
	logDebug(fmt.Sprintf("CA: fmtSrc: %s, fmtDst: %s", fmtSrc, fmtDst))

	data = data[4:]
	// Note: Format codes may differ; format conversion is allowed per spec.
	// Additional parsing for PAN/token, KSN, etc. should be implemented here for full compliance.

	// Decrypt PIN block under source TPK
	inPin, err := hex.DecodeString(pinHex)
	if err != nil {
		logDebug("CA: failed to decode pinHex")
		return nil, errorcodes.Err15
	}
	logDebug(fmt.Sprintf("CA: srcClear: %x", srcClear))
	srcCipher, err := des.NewTripleDESCipher(prepareTripleDESKey(srcClear))
	if err != nil {
		logDebug(fmt.Sprintf("CA: tpk cipher error: %v", err))
		return nil, fmt.Errorf("tpk cipher: %w", err)
	}
	plain := make([]byte, len(inPin))
	srcCipher.Decrypt(plain, inPin)
	logDebug(fmt.Sprintf("CA: decrypted PIN block: %x", plain))

	logDebug(fmt.Sprintf("CA: dstClear: %x", dstClear))
	// Encrypt under destination key
	dstCipher, err := des.NewTripleDESCipher(prepareTripleDESKey(dstClear))
	if err != nil {
		logDebug(fmt.Sprintf("CA: zpk cipher error: %v", err))
		return nil, fmt.Errorf("zpk cipher: %w", err)
	}
	out := make([]byte, len(plain))
	dstCipher.Encrypt(out, plain)
	logDebug(fmt.Sprintf("CA: encrypted PIN block: %x", out))

	// Build response: CB + 00 + pin length + PIN block + format
	resp := []byte("CB00")
	resp = append(resp, pinLen...)
	resp = append(resp, cryptoutils.Raw2B(out)...)
	resp = append(resp, fmtDst...)
	logDebug(fmt.Sprintf("CA: final response: %s", string(resp)))

	return resp, nil
}
