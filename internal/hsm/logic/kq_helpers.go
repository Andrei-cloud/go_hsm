package logic

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

type kqInput struct {
	mode            byte
	scheme          byte
	clearMKAC       []byte
	panPsn          []byte
	atc             []byte
	un              []byte
	transactionData []byte
	arqc            []byte
	arc             []byte
}

// extractBytes extracts a slice of bytes from the input at the current index with a given length.
// It updates the index and returns an error if the input is too short.
func extractBytes(input []byte, index *int, length int) ([]byte, error) {
	if len(input) < *index+length {
		return nil, errorcodes.Err15
	}
	data := input[*index : *index+length]
	*index += length
	return data, nil
}

// parseModeAndScheme parses the mode and scheme from the input byte slice.
func parseModeAndScheme(input []byte) (mode byte, scheme byte, err error) {
	if len(input) < 2 {
		return 0, 0, errorcodes.Err15
	}

	mode = input[0] - '0'
	if mode > 2 {
		return 0, 0, errorcodes.Err68
	}

	scheme = input[1] - '0'
	if scheme != 0 {
		return 0, 0, errorcodes.Err68
	}
	return mode, scheme, nil
}

// readMKACHex reads the MK-AC hex string and determines if it's a variant LMK.
func readMKACHex(input []byte, index *int) (string, bool, error) {
	const minMKACLength = 32 // Minimum hex characters for MK-AC

	var mkacHex string
	isVariantLMK := false

	if len(input) < *index+1 {
		return "", false, errorcodes.Err15
	}

	if input[*index] == 'U' {
		isVariantLMK = true
		mkacBytes, err := extractBytes(input, index, 1+minMKACLength) // 'U' + 32 hex chars
		if err != nil {
			return "", false, err
		}
		mkacHex = string(mkacBytes[1:])
	} else {
		mkacBytes, err := extractBytes(input, index, minMKACLength) // 32 hex chars
		if err != nil {
			return "", false, err
		}
		mkacHex = string(mkacBytes)
	}
	return mkacHex, isVariantLMK, nil
}

// decryptAndValidateMKAC decrypts the MK-AC and performs parity check.
func decryptAndValidateMKAC(mkacHex string, isVariantLMK bool) ([]byte, error) {
	encryptedMKAC, err := hex.DecodeString(mkacHex)
	if err != nil {
		return nil, errorcodes.Err15
	}

	var clearMKAC []byte
	if isVariantLMK {
		clearMKAC, err = LMKProviderInstance.DecryptUnderLMK(encryptedMKAC, "109", 'U')
	} else {
		clearMKAC, err = LMKProviderInstance.DecryptUnderLMK(encryptedMKAC, "109", '0')
	}
	if err != nil {
		if hsmErr, ok := err.(errorcodes.HSMError); ok {
			return nil, hsmErr
		}
		return nil, errorcodes.Err10
	}

	if !cryptoutils.CheckKeyParity(clearMKAC) {
		return nil, errorcodes.Err10
	}

	if len(clearMKAC) != 16 {
		return nil, errorcodes.Err27
	}

	return clearMKAC, nil
}

// parseMKAC parses the MK-AC field from the input byte slice.
func parseMKAC(input []byte, index *int) ([]byte, error) {
	mkacHex, isVariantLMK, err := readMKACHex(input, index)
	if err != nil {
		return nil, err
	}

	return decryptAndValidateMKAC(mkacHex, isVariantLMK)
}

// parseTransactionData parses the Transaction Data field from the input byte slice.
func parseTransactionData(input []byte, index *int) ([]byte, error) {
	dataLenHexBytes, err := extractBytes(input, index, 2) // 2 hex chars for length
	if err != nil {
		return nil, err
	}
	dataLen, err := hex.DecodeString(string(dataLenHexBytes))
	if err != nil || len(dataLen) != 1 {
		return nil, errorcodes.Err15
	}
	transactionDataLength := int(dataLen[0])

	if transactionDataLength < 1 || transactionDataLength > 252 {
		return nil, errorcodes.Err80
	}

	return extractBytes(input, index, transactionDataLength)
}

// parseARQC parses the ARQC field from the input byte slice.
func parseARQC(input []byte, index *int) ([]byte, error) {
	delimiter, err := extractBytes(input, index, 1)
	if err != nil || delimiter[0] != ';' {
		return nil, errorcodes.Err15
	}
	return extractBytes(input, index, 8) // 8 bytes for ARQC
}

// parseARC parses the ARC field from the input byte slice, if applicable.
func parseARC(input []byte, index *int, mode byte) ([]byte, error) {
	var arc []byte
	if mode == 1 || mode == 2 {
		arcBytes, err := extractBytes(input, index, 2) // 2 bytes for ARC
		if err != nil {
			return nil, err
		}
		arc = arcBytes
	}
	return arc, nil
}

func parseKQInput(input []byte) (*kqInput, error) {
	if len(input) < 4 { // Minimum length for mode, scheme, and start of MK-AC
		return nil, errorcodes.Err15
	}

	index := 0
	mode, scheme, err := parseModeAndScheme(input[index:])
	if err != nil {
		return nil, err
	}
	index += 2 // Move past mode and scheme

	clearMKAC, err := parseMKAC(input, &index)
	if err != nil {
		return nil, err
	}

	panPsn, err := extractBytes(input, &index, 8) // 8 bytes for PAN/PSN
	if err != nil {
		return nil, err
	}

	atc, err := extractBytes(input, &index, 2) // 2 bytes for ATC
	if err != nil {
		return nil, err
	}

	un, err := extractBytes(input, &index, 4) // 4 bytes for UN
	if err != nil {
		return nil, err
	}

	transactionData, err := parseTransactionData(input, &index)
	if err != nil {
		return nil, err
	}

	arqc, err := parseARQC(input, &index)
	if err != nil {
		return nil, err
	}

	arc, err := parseARC(input, &index, mode)
	if err != nil {
		return nil, err
	}

	return &kqInput{
		mode:            mode,
		scheme:          scheme,
		clearMKAC:       clearMKAC,
		panPsn:          panPsn,
		atc:             atc,
		un:              un,
		transactionData: transactionData,
		arqc:            arqc,
		arc:             arc,
	}, nil
}

func verifyARQC(data *kqInput) error {
	pan := fmt.Sprintf("%x", data.panPsn[:7])
	psn := fmt.Sprintf("%02x", data.panPsn[7])

	calculatedARQC, err := cryptoutils.GenerateARQC10(
		data.clearMKAC,
		data.transactionData,
		pan,
		psn,
	)
	if err != nil {
		return errorcodes.Err42
	}

	if !bytes.Equal(calculatedARQC, data.arqc) {
		return errorcodes.Err01
	}

	return nil
}

func generateARPC(data *kqInput) ([]byte, error) {
	pan := fmt.Sprintf("%x", data.panPsn[:7])
	psn := fmt.Sprintf("%02x", data.panPsn[7])

	arpc, err := cryptoutils.GenerateARPC10(data.clearMKAC, data.arqc, data.arc, pan, psn)
	if err != nil {
		return nil, errorcodes.Err42
	}

	return arpc, nil
}
