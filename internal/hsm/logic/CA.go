// filepath: internal/hsm/logic/CA.go
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

	// Get the source format
	srcFormat, err := hsm.GetPinBlockFormatFromThalesCode(fmtSrc)
	if err != nil {
		logDebug(fmt.Sprintf("CA: invalid source format code: %s", fmtSrc))
		return nil, errorcodes.Err15
	}

	// Get the destination format
	dstFormat, err := hsm.GetPinBlockFormatFromThalesCode(fmtDst)
	if err != nil {
		logDebug(fmt.Sprintf("CA: invalid destination format code: %s", fmtDst))
		return nil, errorcodes.Err15
	}

	data = data[4:]

	// Process any additional data based on format requirements (PAN, UDK, etc.)
	var panOrUdk string
	switch srcFormat {
	case pinblock.ISO0, pinblock.PLUSNETWORK, pinblock.MASTERCARDPAYNOWPAYLATER:
		if len(data) < 12 {
			logDebug("CA: missing PAN for PAN-based format")
			return nil, errorcodes.Err15
		}
		panOrUdk = string(data[:12])
		data = data[12:]
	case pinblock.VISANEWPINONLY:
		if len(data) < 16 {
			logDebug("CA: missing UDK for VISA format 41")
			return nil, errorcodes.Err15
		}
		panOrUdk = string(data[:16])
		data = data[16:]
	case pinblock.VISANEWOLDIN:
		if len(data) < 20 { // Need both old PIN and UDK
			logDebug("CA: missing old PIN/UDK for VISA format 42")
			return nil, errorcodes.Err15
		}
		oldPin := string(data[:4]) // Assuming 4-digit old PIN
		udk := string(data[4:20])
		panOrUdk = oldPin + "|" + udk
		data = data[20:]
	}

	// Decrypt PIN block under source TPK
	inPin, err := hex.DecodeString(pinHex)
	if err != nil {
		logDebug("CA: failed to decode pinHex")
		return nil, errorcodes.Err15
	}
	srcCipher, err := des.NewTripleDESCipher(prepareTripleDESKey(srcClear))
	if err != nil {
		logDebug(fmt.Sprintf("CA: tpk cipher error: %v", err))
		return nil, fmt.Errorf("tpk cipher: %w", err)
	}
	plain := make([]byte, len(inPin))
	srcCipher.Decrypt(plain, inPin)
	plainHex := hex.EncodeToString(plain)
	logDebug(fmt.Sprintf("CA: decrypted PIN block: %x", plain))

	// Extract the clear PIN from the decrypted block
	clearPin, err := pinblock.DecodePinBlock(plainHex, panOrUdk, srcFormat)
	if err != nil {
		logDebug(fmt.Sprintf("CA: failed to decode PIN block: %v", err))
		return nil, errorcodes.Err15
	}

	// Re-encode the PIN in the destination format
	newBlockHex, err := pinblock.EncodePinBlock(clearPin, panOrUdk, dstFormat)
	if err != nil {
		logDebug(fmt.Sprintf("CA: failed to encode PIN block: %v", err))
		return nil, errorcodes.Err15
	}

	// Encrypt the new block under destination key
	newBlockBytes, err := hex.DecodeString(newBlockHex)
	if err != nil {
		logDebug("CA: failed to decode new PIN block hex")
		return nil, errorcodes.Err15
	}
	dstCipher, err := des.NewTripleDESCipher(prepareTripleDESKey(dstClear))
	if err != nil {
		logDebug(fmt.Sprintf("CA: zpk cipher error: %v", err))
		return nil, fmt.Errorf("zpk cipher: %w", err)
	}
	out := make([]byte, len(newBlockBytes))
	dstCipher.Encrypt(out, newBlockBytes)
	logDebug(fmt.Sprintf("CA: encrypted PIN block: %x", out))

	// Update PIN length from actual clear PIN length
	pinLen = []byte(fmt.Sprintf("%02d", len(clearPin)))

	// Build response: CB + 00 + pin length + PIN block + format
	resp := []byte("CB00")
	resp = append(resp, pinLen...)
	resp = append(resp, cryptoutils.Raw2B(out)...)
	resp = append(resp, fmtDst...)
	logDebug(fmt.Sprintf("CA: final response: %s", string(resp)))

	return resp, nil
}
