package logic

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/common"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteKQ implements the KQ HSM command for ARQC verification and/or ARPC generation.
// Command supports Visa VIS CVN 10 (scheme 0) with modes 0, 1, 2.
func ExecuteKQ(input []byte) ([]byte, error) {
	logInfo("KQ: Starting ARQC/ARPC command execution")
	logDebug(fmt.Sprintf("KQ: Input length: %d, hex: %x", len(input), input))

	// Minimum input length: mode(1) + scheme(1) + MK-AC(32H minimum) + PAN/PSN(8B) + ATC(2B) + UN(4B) + datalen(2H) + ';' + ARQC(8B)
	// Note: MK-AC can be 32H (standard) or 'U'+32H (variant LMK)
	const minDataLengthStandard = 1 + 1 + 32 + 8 + 2 + 4 + 2 + 1 + 8

	// Initial check for absolute minimum (mode + scheme + at least some MK-AC data).
	if len(input) < 4 {
		logError("KQ: Input data too short")
		return nil, errorcodes.Err15
	}

	// Parse mode.
	mode := input[0] - '0'
	logDebug(fmt.Sprintf("KQ: Mode: %d", mode))

	// Parse scheme.
	scheme := input[1] - '0'
	logDebug(fmt.Sprintf("KQ: Scheme: %d", scheme))

	// Validate scheme first - only support scheme 0.
	if scheme != 0 {
		logError(fmt.Sprintf("KQ: Unsupported scheme: %d", scheme))
		return nil, errorcodes.Err68
	}

	// Validate mode - only support modes 0, 1, 2 for scheme 0.
	if mode > 2 {
		logError(fmt.Sprintf("KQ: Unsupported mode: %d", mode))
		return nil, errorcodes.Err68
	}

	index := 2

	// Parse MK-AC - check for variant scheme indicator first.
	var mkacHex string
	var isVariantLMK bool
	var requiredLength int

	// Check if the next character is 'U' (variant LMK indicator).
	if len(input) < index+1 {
		logError("KQ: Input too short for MK-AC")
		return nil, errorcodes.Err15
	}

	if input[index] == 'U' {
		// Variant LMK format: 'U' + 32 hex characters.
		isVariantLMK = true
		requiredLength = minDataLengthStandard + 1 // Add 1 for the 'U' prefix.

		if len(input) < requiredLength {
			logError("KQ: Input too short for variant LMK format")
			return nil, errorcodes.Err15
		}

		if len(input) < index+1+32 {
			logError("KQ: Input too short for variant LMK MK-AC")
			return nil, errorcodes.Err15
		}
		mkacHex = string(input[index+1 : index+1+32])
		index += 1 + 32
		logDebug(fmt.Sprintf("KQ: Variant LMK MK-AC (hex): %s", mkacHex))
	} else {
		// Standard format: 32 hex characters.
		isVariantLMK = false
		requiredLength = minDataLengthStandard

		if len(input) < requiredLength {
			logError("KQ: Input too short for standard format")
			return nil, errorcodes.Err15
		}

		if len(input) < index+32 {
			logError("KQ: Input too short for standard MK-AC")
			return nil, errorcodes.Err15
		}
		mkacHex = string(input[index : index+32])
		index += 32
		logDebug(fmt.Sprintf("KQ: Standard MK-AC (hex): %s", mkacHex))
	}

	encryptedMKAC, err := hex.DecodeString(mkacHex)
	if err != nil {
		logError("KQ: Invalid MK-AC format")
		return nil, errorcodes.Err15
	}

	// Decrypt MK-AC under appropriate LMK scheme.
	var clearMKAC []byte
	if isVariantLMK {
		// Decrypt under LMK pair 28-29 variant 1 (key type 109 for MK-AC).
		clearMKAC, err = LMKProviderInstance.DecryptUnderLMK(encryptedMKAC, "109", 'U')
	} else {
		// Decrypt under standard LMK (key type 109 for MK-AC).
		clearMKAC, err = LMKProviderInstance.DecryptUnderLMK(encryptedMKAC, "109", '0')
	}

	if err != nil {
		logError(fmt.Sprintf("KQ: MK-AC decryption failed: %v", err))
		if hsmErr, ok := err.(errorcodes.HSMError); ok {
			return nil, hsmErr
		}

		return nil, errorcodes.Err10
	}

	logInfo("KQ: Verifying MK-AC parity.")
	if !cryptoutils.CheckKeyParity(clearMKAC) {
		logError("KQ: MK-AC parity check failed")

		return nil, errorcodes.Err10
	}

	if len(clearMKAC) != 16 {
		logError(fmt.Sprintf("KQ: MK-AC incorrect length: %d bytes, expected 16", len(clearMKAC)))
		return nil, errorcodes.Err27
	}

	logDebug(fmt.Sprintf("KQ: Clear MK-AC: %s", common.FormatData(clearMKAC)))

	// Parse PAN/PAN Sequence No (8 bytes pre-formatted).
	if len(input) < index+8 {
		logError("KQ: Input too short for PAN/PSN")
		return nil, errorcodes.Err15
	}
	panPsn := input[index : index+8]
	logDebug(fmt.Sprintf("KQ: PAN/PSN: %x", panPsn))
	index += 8

	// Parse ATC (2 bytes).
	if len(input) < index+2 {
		logError("KQ: Input too short for ATC")
		return nil, errorcodes.Err15
	}
	atc := input[index : index+2]
	logDebug(fmt.Sprintf("KQ: ATC: %x", atc))
	index += 2

	// Parse UN (4 bytes).
	if len(input) < index+4 {
		logError("KQ: Input too short for UN")
		return nil, errorcodes.Err15
	}
	un := input[index : index+4]
	logDebug(fmt.Sprintf("KQ: UN: %x", un))
	index += 4

	// Parse Transaction Data Length (2 hex characters).
	if len(input) < index+2 {
		logError("KQ: Input too short for Transaction Data Length")
		return nil, errorcodes.Err15
	}
	dataLenHex := string(input[index : index+2])
	dataLen, err := hex.DecodeString(dataLenHex)
	if err != nil || len(dataLen) != 1 {
		logError("KQ: Invalid Transaction Data Length format")
		return nil, errorcodes.Err15
	}
	transactionDataLength := int(dataLen[0])
	logDebug(fmt.Sprintf("KQ: Transaction data length: %d", transactionDataLength))
	index += 2

	// Validate transaction data length.
	if transactionDataLength < 1 || transactionDataLength > 255 {
		logError("KQ: Invalid transaction data length")
		return nil, errorcodes.Err80
	}

	// Parse Transaction Data.
	if len(input) < index+transactionDataLength {
		logError("KQ: Input too short for Transaction Data")
		return nil, errorcodes.Err15
	}
	transactionData := input[index : index+transactionDataLength]
	logDebug(fmt.Sprintf("KQ: Transaction data: %x", transactionData))
	index += transactionDataLength

	// Parse delimiter.
	if len(input) < index+1 || input[index] != ';' {
		logError("KQ: Missing transaction data delimiter")
		return nil, errorcodes.Err15
	}
	index++

	// Parse ARQC (8 bytes).
	if len(input) < index+8 {
		logError("KQ: Input too short for ARQC")
		return nil, errorcodes.Err15
	}
	arqc := input[index : index+8]
	logDebug(fmt.Sprintf("KQ: ARQC: %x", arqc))
	index += 8

	// Parse ARC (optional, for modes 1 and 2).
	var arc []byte
	if mode == 1 || mode == 2 {
		if len(input) < index+2 {
			logError("KQ: Input too short for ARC")
			return nil, errorcodes.Err15
		}

		arc = input[index : index+2]
		logDebug(fmt.Sprintf("KQ: ARC: %x", arc))
	}

	// Extract PAN and PSN from PAN/PSN field for key derivation.
	pan := fmt.Sprintf("%x", panPsn[:7])  // First 7 bytes as PAN
	psn := fmt.Sprintf("%02x", panPsn[7]) // Last byte as PSN

	logDebug(fmt.Sprintf("KQ: PAN: %s, PSN: %s", pan, psn))

	logInfo("KQ: Processing based on mode.")

	var response []byte

	switch mode {
	case 0:
		// Mode 0: ARQC verification only.
		logInfo("KQ: Mode 0 - ARQC verification only")

		calculatedARQC, err := cryptoutils.GenerateARQC10(clearMKAC, transactionData, pan, psn)
		if err != nil {
			logError(fmt.Sprintf("KQ: ARQC calculation failed: %v", err))
			return nil, errorcodes.Err42
		}

		logDebug(fmt.Sprintf("KQ: Calculated ARQC: %x", calculatedARQC))
		logDebug(fmt.Sprintf("KQ: Received ARQC: %x", arqc))

		if !bytes.Equal(calculatedARQC, arqc) {
			logError("KQ: ARQC verification failed")
			return nil, errorcodes.Err01
		}

		logInfo("KQ: ARQC verification successful")
		response = []byte("KR00")

	case 1:
		// Mode 1: ARQC verification and ARPC generation.
		logInfo("KQ: Mode 1 - ARQC verification and ARPC generation")

		calculatedARQC, err := cryptoutils.GenerateARQC10(clearMKAC, transactionData, pan, psn)
		if err != nil {
			logError(fmt.Sprintf("KQ: ARQC calculation failed: %v", err))
			return nil, errorcodes.Err42
		}

		if !bytes.Equal(calculatedARQC, arqc) {
			logError("KQ: ARQC verification failed")
			return nil, errorcodes.Err01
		}

		// Generate ARPC.
		arpc, err := cryptoutils.GenerateARPC10(clearMKAC, arqc, arc, pan, psn)
		if err != nil {
			logError(fmt.Sprintf("KQ: ARPC generation failed: %v", err))
			return nil, errorcodes.Err42
		}

		logInfo("KQ: ARQC verification and ARPC generation successful")
		response = append([]byte("KR00"), []byte(hex.EncodeToString(arpc))...)

	case 2:
		// Mode 2: ARPC generation only.
		logInfo("KQ: Mode 2 - ARPC generation only")

		arpc, err := cryptoutils.GenerateARPC10(clearMKAC, arqc, arc, pan, psn)
		if err != nil {
			logError(fmt.Sprintf("KQ: ARPC generation failed: %v", err))
			return nil, errorcodes.Err42
		}

		logInfo("KQ: ARPC generation successful")
		response = append([]byte("KR00"), []byte(hex.EncodeToString(arpc))...)
	}

	logDebug(fmt.Sprintf("KQ: Final response: %s", string(response)))

	return response, nil
}
