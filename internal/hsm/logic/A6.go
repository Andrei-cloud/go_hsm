package logic

import (
	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteA6 imports a key received under a ZMK and returns it under the LMK.
// The request is the key type (3H), the ZMK under LMK, the key under the ZMK
// (16H, 'X' and 32H, or 'Y' and 48H, encrypted in ECB mode) and the key scheme
// under LMK (1A: 'Z', 'U' or 'T'). The response is "A7" + "00" + the key under
// LMK + its check value (6H). An imported key with a parity error is still
// returned, with "01" in place of "00", as a warning.
func ExecuteA6(input []byte) ([]byte, error) {
	logInfo("A6: importing a key under ZMK")

	if len(input) < keyTypeLength {
		logError("A6: input too short")
		return nil, errorcodes.Err15
	}

	keyType := string(input[:keyTypeLength])

	clearZMK, data, err := readZMK("A6", input[keyTypeLength:])
	if err != nil {
		return nil, err
	}

	encryptedKey, data, err := readKeyUnderZMK("A6", data)
	if err != nil {
		return nil, err
	}

	if isAllZero(encryptedKey) {
		logError("A6: key under ZMK is all zeros")
		return nil, errorcodes.Err11
	}

	lmkScheme, err := readLMKScheme("A6", data, len(encryptedKey))
	if err != nil {
		return nil, err
	}

	clearKey, err := underZMK(clearZMK, encryptedKey, false)
	if err != nil {
		return nil, err
	}

	lmkKey, err := LMKProviderInstance.EncryptUnderLMK(clearKey, keyType, lmkScheme)
	if err != nil {
		logError("A6: encryption under LMK failed")
		return nil, errorcodes.Err04
	}

	kcv, err := cryptoutils.KeyCV(cryptoutils.Raw2B(clearKey), kcvDigits)
	if err != nil {
		logError("A6: check value calculation failed")
		return nil, errorcodes.Err68
	}

	resp := []byte("A700")

	if !cryptoutils.CheckKeyParity(clearKey) {
		logInfo("A6: imported key parity error")

		resp = []byte("A701")
	}

	if lmkScheme == 'Z' {
		resp = append(resp, cryptoutils.Raw2B(lmkKey[:singleKeyLength])...)
	} else {
		resp = appendEncryptedKeyToResponse(resp, lmkScheme, lmkKey)
	}

	return append(resp, kcv...), nil
}
