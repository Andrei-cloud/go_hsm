package logic

import (
	"encoding/hex"
	"fmt"

	"github.com/andrei-cloud/go_hsm/pkg/common"
)

// ExecuteKQ implements the KQ HSM command for ARQC verification and/or ARPC generation.
// Command supports Visa VIS CVN 10 (scheme 0) with modes 0, 1, 2.
func ExecuteKQ(input []byte) ([]byte, error) {
	logInfo("KQ: Starting ARQC/ARPC command execution")
	logDebug(fmt.Sprintf("KQ: Input length: %d, hex: %x", len(input), input))

	data, err := parseKQInput(input)
	if err != nil {
		logError(fmt.Sprintf("KQ: Failed to parse input: %v", err))
		return nil, err
	}

	logDebug(fmt.Sprintf("KQ: Clear MK-AC: %s", common.FormatData(data.clearMKAC)))
	logDebug(fmt.Sprintf("KQ: PAN/PSN: %x", data.panPsn))
	logDebug(fmt.Sprintf("KQ: ATC: %x", data.atc))
	logDebug(fmt.Sprintf("KQ: UN: %x", data.un))
	logDebug(fmt.Sprintf("KQ: Transaction data: %x", data.transactionData))
	logDebug(fmt.Sprintf("KQ: ARQC: %x", data.arqc))
	if data.arc != nil {
		logDebug(fmt.Sprintf("KQ: ARC: %x", data.arc))
	}

	var response []byte

	switch data.mode {
	case 0:
		logInfo("KQ: Mode 0 - ARQC verification only")
		if err := verifyARQC(data); err != nil {
			logError(fmt.Sprintf("KQ: ARQC verification failed: %v", err))
			return nil, err
		}
		logInfo("KQ: ARQC verification successful")
		response = []byte("KR00")

	case 1:
		logInfo("KQ: Mode 1 - ARQC verification and ARPC generation")
		if err := verifyARQC(data); err != nil {
			logError(fmt.Sprintf("KQ: ARQC verification failed: %v", err))
			return nil, err
		}
		arpc, err := generateARPC(data)
		if err != nil {
			logError(fmt.Sprintf("KQ: ARPC generation failed: %v", err))
			return nil, err
		}
		logInfo("KQ: ARQC verification and ARPC generation successful")
		response = append([]byte("KR00"), []byte(hex.EncodeToString(arpc))...)

	case 2:
		logInfo("KQ: Mode 2 - ARPC generation only")
		arpc, err := generateARPC(data)
		if err != nil {
			logError(fmt.Sprintf("KQ: ARPC generation failed: %v", err))
			return nil, err
		}
		logInfo("KQ: ARPC generation successful")
		response = append([]byte("KR00"), []byte(hex.EncodeToString(arpc))...)
	}

	logDebug(fmt.Sprintf("KQ: Final response: %s", string(response)))

	return response, nil
}