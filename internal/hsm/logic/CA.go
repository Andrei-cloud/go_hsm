// filepath: internal/hsm/logic/CA.go
package logic

import (
	"crypto/des"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/internal/hsm"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
	"github.com/andrei-cloud/go_hsm/pkg/pinblock"
)

// ExecuteCA translates a PIN block encrypted under a TPK to one encrypted under a ZPK or BDK under Variant LMK.
func ExecuteCA(input []byte) ([]byte, error) {
	data := input
	logInfo("CA: Starting PIN block translation.")
	logDebug(fmt.Sprintf("CA: Input length: %d, hex: %x", len(input), input))

	// Validate minimum input length: mode(1) + keytype(3) + scheme(0|1) +
	// key(16|32|48) + scheme(0|1) + key(16|32|48) + pin length(2) + pin block(16) + format(2)
	if len(data) < 1+3+16+16+2+16+2 {
		logError("CA: Insufficient data length")
		return nil, errorcodes.Err15
	}

	// Parse source TPK
	logInfo("CA: Processing source TPK.")
	srcScheme := data[0]
	logDebug(fmt.Sprintf("CA: Source key scheme: %c", srcScheme))
	rawSrc := getKeyLength(srcScheme)
	hexSrc := rawSrc * 2
	if srcScheme != 'U' && srcScheme != 'T' && srcScheme != 'X' {
		logError("CA: Invalid source key scheme")
		return nil, errorcodes.Err15
	}
	if len(data) < 1+hexSrc {
		logError("CA: Insufficient data for source key")
		return nil, errorcodes.Err15
	}
	srcHex := string(data[1 : 1+hexSrc])
	logDebug(fmt.Sprintf("CA: Source key hex: %s", srcHex))
	data = data[1+hexSrc:]
	srcBytes, err := hex.DecodeString(srcHex)
	if err != nil {
		logError("CA: Invalid source key format")
		return nil, errorcodes.Err15
	}

	logInfo("CA: Decrypting source key under LMK.")
	srcClear, err := LMKProviderInstance.DecryptUnderLMK(srcBytes, "002", srcScheme)
	if err != nil {
		logError("CA: Failed to decrypt source key under LMK")
		return nil, errorcodes.Err68
	}
	logDebug(fmt.Sprintf("CA: Source key decrypted value: %x", srcClear))

	// Parse optional destination flag
	logInfo("CA: Processing destination key parameters.")
	keyType := "001"
	switch data[0] {
	case '*':
		keyType = "009"
		logDebug("CA: Destination flag is * (keyType=009)")
		data = data[1:]
	case '~':
		keyType = "609"
		logDebug("CA: Destination flag is ~ (keyType=609)")
		data = data[1:]
	}

	// Parse destination key
	dstScheme := data[0]
	logDebug(fmt.Sprintf("CA: Destination key scheme: %c", dstScheme))
	rawDst := getKeyLength(dstScheme)
	hexDst := rawDst * 2
	if dstScheme != 'U' && dstScheme != 'T' && dstScheme != 'X' {
		logError("CA: Invalid destination key scheme")
		return nil, errorcodes.Err15
	}
	if len(data) < 1+hexDst {
		logError("CA: Insufficient data for destination key")
		return nil, errorcodes.Err15
	}
	dstHex := string(data[1 : 1+hexDst])
	logDebug(fmt.Sprintf("CA: Destination key hex: %s", dstHex))
	data = data[1+hexDst:]
	dstBytes, err := hex.DecodeString(dstHex)
	if err != nil {
		logError("CA: Invalid destination key format")
		return nil, errorcodes.Err15
	}

	logInfo("CA: Decrypting destination key under LMK.")
	dstClear, err := LMKProviderInstance.DecryptUnderLMK(dstBytes, keyType, dstScheme)
	if err != nil {
		logError("CA: Failed to decrypt destination key under LMK")
		return nil, errorcodes.Err68
	}
	logDebug(fmt.Sprintf("CA: Destination key decrypted value: %x", dstClear))

	// verify source key parity after destination key scheme and decryption validation.
	logInfo("CA: Verifying source key parity.")
	if !cryptoutils.CheckKeyParity(srcClear) {
		logError("CA: Source key parity check failed")
		return nil, errorcodes.Err10
	}

	logInfo("CA: Processing PIN block parameters.")
	pinLen := data[:2]
	logDebug(fmt.Sprintf("CA: PIN length: %s", string(pinLen)))
	data = data[2:]

	// Parse PIN block hex
	pinHex := string(data[:16])
	logDebug(fmt.Sprintf("CA: PIN block hex: %s", pinHex))
	data = data[16:]

	// Parse source and destination format codes separately
	fmtSrc := string(data[:2])
	fmtDst := string(data[2:4])
	logDebug(fmt.Sprintf("CA: Source format: %s, Destination format: %s", fmtSrc, fmtDst))

	// Get the source format
	logInfo("CA: Validating PIN block formats.")
	srcFormat, err := hsm.GetPinBlockFormatFromThalesCode(fmtSrc)
	if err != nil {
		logError(fmt.Sprintf("CA: Invalid source format code: %s", fmtSrc))
		return nil, errorcodes.Err15
	}

	// Get the destination format
	dstFormat, err := hsm.GetPinBlockFormatFromThalesCode(fmtDst)
	if err != nil {
		logError(fmt.Sprintf("CA: Invalid destination format code: %s", fmtDst))
		return nil, errorcodes.Err15
	}

	data = data[4:]

	// Process any additional data based on format requirements (PAN, UDK, etc.)
	logInfo("CA: Processing format-specific parameters.")
	var panOrUdk string
	switch srcFormat {
	case pinblock.ISO0, pinblock.PLUSNETWORK, pinblock.MASTERCARDPAYNOWPAYLATER:
		if len(data) < 12 {
			logError("CA: Missing PAN for PAN-based format")
			return nil, errorcodes.Err15
		}
		panOrUdk = string(data[:12])
		logDebug(fmt.Sprintf("CA: Using PAN: %s", panOrUdk))
		_ = data[12:]
	case pinblock.VISANEWPINONLY:
		if len(data) < 16 {
			logError("CA: Missing UDK for VISA format 41")
			return nil, errorcodes.Err15
		}
		panOrUdk = string(data[:16])
		logDebug(fmt.Sprintf("CA: Using UDK: %s", panOrUdk))
		_ = data[16:]
	case pinblock.VISANEWOLDIN:
		if len(data) < 20 { // Need both old PIN and UDK
			logError("CA: Missing old PIN/UDK for VISA format 42")
			return nil, errorcodes.Err15
		}
		oldPin := string(data[:4]) // Assuming 4-digit old PIN
		udk := string(data[4:20])
		panOrUdk = oldPin + "|" + udk
		logDebug(fmt.Sprintf("CA: Using old PIN and UDK: %s", panOrUdk))
		_ = data[20:]
	}

	// Decrypt PIN block under source TPK
	logInfo("CA: Decrypting PIN block under source TPK.")
	inPin, err := hex.DecodeString(pinHex)
	if err != nil {
		logError("CA: Failed to decode PIN block hex")
		return nil, errorcodes.Err15
	}
	srcCipher, err := des.NewTripleDESCipher(cryptoutils.PrepareTripleDESKey(srcClear))
	if err != nil {
		logError(fmt.Sprintf("CA: TPK cipher initialization error: %v", err))
		return nil, fmt.Errorf("tpk cipher: %w", err)
	}
	plain := make([]byte, len(inPin))
	srcCipher.Decrypt(plain, inPin)
	plainHex := hex.EncodeToString(plain)
	logDebug(fmt.Sprintf("CA: Decrypted PIN block: %x", plain))

	// Extract the clear PIN from the decrypted block
	logInfo("CA: Extracting clear PIN from decrypted block.")
	clearPin, err := pinblock.DecodePinBlock(plainHex, panOrUdk, srcFormat)
	if err != nil {
		logError(fmt.Sprintf("CA: Failed to decode PIN block: %v", err))
		return nil, errorcodes.Err15
	}

	// Re-encode the PIN in the destination format
	logInfo("CA: Re-encoding PIN in destination format.")
	newBlockHex, err := pinblock.EncodePinBlock(clearPin, panOrUdk, dstFormat)
	if err != nil {
		logError(fmt.Sprintf("CA: Failed to encode PIN block: %v", err))
		return nil, errorcodes.Err15
	}

	// Encrypt the new block under destination key
	logInfo("CA: Encrypting new PIN block under destination key.")
	newBlockBytes, err := hex.DecodeString(newBlockHex)
	if err != nil {
		logError("CA: Failed to decode new PIN block hex")
		return nil, errorcodes.Err15
	}
	dstCipher, err := des.NewTripleDESCipher(cryptoutils.PrepareTripleDESKey(dstClear))
	if err != nil {
		logError(fmt.Sprintf("CA: ZPK cipher initialization error: %v", err))
		return nil, fmt.Errorf("zpk cipher: %w", err)
	}
	out := make([]byte, len(newBlockBytes))
	dstCipher.Encrypt(out, newBlockBytes)
	logDebug(fmt.Sprintf("CA: Encrypted PIN block: %x", out))

	// Update PIN length from actual clear PIN length
	logInfo("CA: Formatting response.")
	pinLen = fmt.Appendf([]byte{}, "%02d", len(clearPin))

	// Build response: CB + 00 + pin length + PIN block + format
	resp := slices.Concat([]byte("CB00"), pinLen, cryptoutils.Raw2B(out), []byte(fmtDst))

	logDebug(fmt.Sprintf("CA: Final response: %s", string(resp)))

	return resp, nil
}
