package logic

import (
	"crypto/des"
	"encoding/hex"
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/internal/hsm"
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
// Format: [TPK scheme + key](optional) + PIN block + source format code + destination format code + account number.
func ExecuteDC(
	input []byte,
	decryptUnderLMK func([]byte) ([]byte, error),
	_ func([]byte) ([]byte, error), // Placeholder for encryptUnderLMK, unused in DC.
	logFn func(string),
) ([]byte, error) {
	data := input
	// Minimum length: TPK (16) + PIN Block (16) + Source PIN Block Format (2) + Dest PIN Block Format (2) + Account Number (12)
	if len(data) < 16+16+2+2+12 {
		logFn("DC: insufficient data length")

		return nil, errorcodes.Err15
	}

	// Extract and decrypt TPK
	encryptedTPKHex := string(data[:16])
	data = data[16:]
	logFn(fmt.Sprintf("DC: parsed encrypted TPK: %s", encryptedTPKHex))

	encryptedTPK, err := hex.DecodeString(encryptedTPKHex)
	if err != nil {
		logFn(fmt.Sprintf("DC: invalid TPK hex format: %v", err))

		return nil, errorcodes.Err15
	}

	decryptedTPK, err := decryptUnderLMK(encryptedTPK)
	if err != nil {
		logFn(fmt.Sprintf("DC: failed to decrypt TPK: %v", err))

		return nil, errorcodes.Err68 // Using a generic error as specific TPK error isn't defined.
	}
	logFn(fmt.Sprintf("DC: decrypted TPK length: %d", len(decryptedTPK)))

	// Extract encrypted PIN block
	encryptedPinBlockHex := string(data[:16])
	data = data[16:]
	logFn(fmt.Sprintf("DC: parsed encrypted PIN block: %s", encryptedPinBlockHex))

	// Extract source PIN block format
	sourceFormatCode := string(data[:2])
	data = data[2:]
	logFn(fmt.Sprintf("DC: parsed source PIN block format: %s", sourceFormatCode))

	// Extract destination PIN block format
	destFormatCode := string(data[:2])
	data = data[2:]
	logFn(fmt.Sprintf("DC: parsed destination PIN block format: %s", destFormatCode))

	// Extract account number
	accountNum := string(data[:12])
	logFn(fmt.Sprintf("DC: parsed account number: %s", accountNum))

	// Create TPK cipher
	tpkCipher, err := des.NewTripleDESCipher(decryptedTPK)
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

	// Decrypt PIN block using TPK
	decryptedPinBlock := make([]byte, len(pinBlockBin))
	tpkCipher.Decrypt(decryptedPinBlock, pinBlockBin)
	decryptedPinBlockHex := hex.EncodeToString(decryptedPinBlock)
	logFn(fmt.Sprintf("DC: decrypted PIN block hex: %s", decryptedPinBlockHex))

	// Extract clear PIN from decrypted PIN block
	sourcePinBlockFormat, err := hsm.GetPinBlockFormatFromThalesCode(sourceFormatCode)
	if err != nil {
		logFn(fmt.Sprintf("DC: invalid source pin block format code %s: %v", sourceFormatCode, err))

		return nil, errorcodes.Err23
	}

	clearPIN, err := pinblock.DecodePinBlock(decryptedPinBlockHex, accountNum, sourcePinBlockFormat)
	if err != nil {
		logFn(fmt.Sprintf("DC: failed to extract clear PIN: %v", err))

		return nil, errorcodes.Err20
	}
	logFn(fmt.Sprintf("DC: extracted clear PIN: %s", clearPIN))

	// Encode clear PIN into destination format
	destPinBlockFormat, err := hsm.GetPinBlockFormatFromThalesCode(destFormatCode)
	if err != nil {
		logFn(
			fmt.Sprintf(
				"DC: invalid destination pin block format code %s: %v",
				destFormatCode,
				err,
			),
		)

		return nil, errorcodes.Err23
	}

	destPinBlockHex, err := pinblock.EncodePinBlock(clearPIN, accountNum, destPinBlockFormat)
	if err != nil {
		logFn(fmt.Sprintf("DC: failed to encode PIN to destination format: %v", err))

		return nil, errorcodes.Err68 // Or a more specific error if available.
	}
	logFn(fmt.Sprintf("DC: encoded PIN block in destination format: %s", destPinBlockHex))

	// Encrypt destination PIN block with TPK
	destPinBlockBin, err := hex.DecodeString(destPinBlockHex)
	if err != nil {
		logFn(fmt.Sprintf("DC: failed to decode destination PIN block hex: %v", err))

		return nil, errorcodes.Err15
	}

	encryptedDestPinBlock := make([]byte, len(destPinBlockBin))
	tpkCipher.Encrypt(encryptedDestPinBlock, destPinBlockBin)
	encryptedDestPinBlockHex := hex.EncodeToString(encryptedDestPinBlock)
	logFn(fmt.Sprintf("DC: encrypted destination PIN block: %s", encryptedDestPinBlockHex))

	// Construct response: command code (DD) + error code (00) + encrypted PIN block
	response := "DD" + errorcodes.Err00.CodeOnly() + encryptedDestPinBlockHex

	return []byte(response), nil
}
