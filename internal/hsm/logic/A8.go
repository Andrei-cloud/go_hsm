package logic

import (
	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteA8 exports a key held under the LMK, encrypted under a ZMK. The
// request is the key type (3H), the ZMK under LMK, the key under LMK (16H, 'U'
// and 32H, or 'T' and 48H) and the key scheme under ZMK (1A: 'Z', 'X' or 'Y',
// ECB mode, matching the key's length). The response is "A9" + "00" + the key
// under the ZMK (with its scheme tag, none for 'Z') + its check value (6H).
func ExecuteA8(input []byte) ([]byte, error) {
	logInfo("A8: exporting a key under ZMK")

	if len(input) < keyTypeLength {
		logError("A8: input too short")
		return nil, errorcodes.Err15
	}

	keyType := string(input[:keyTypeLength])

	clearZMK, data, err := readZMK("A8", input[keyTypeLength:])
	if err != nil {
		return nil, err
	}

	lmkScheme, lmkKey, data, err := readKeyUnderLMK(data)
	if err != nil {
		logError("A8: invalid key under LMK")
		return nil, err
	}

	clearKey, err := LMKProviderInstance.DecryptUnderLMK(lmkKey, keyType, lmkScheme)
	if err != nil {
		logError("A8: key decryption failed")
		return nil, errorcodes.Err04
	}

	if !cryptoutils.CheckKeyParity(clearKey) {
		logError("A8: key parity error")
		return nil, errorcodes.Err11
	}

	zoneScheme, err := readZoneScheme("A8", data, len(clearKey))
	if err != nil {
		return nil, err
	}

	zoneKey, err := underZMK(clearZMK, clearKey, true)
	if err != nil {
		return nil, err
	}

	kcv, err := cryptoutils.KeyCV(cryptoutils.Raw2B(clearKey), kcvDigits)
	if err != nil {
		logError("A8: check value calculation failed")
		return nil, errorcodes.Err68
	}

	resp := []byte("A900")
	if zoneScheme != 'Z' {
		resp = append(resp, zoneScheme)
	}

	resp = append(resp, cryptoutils.Raw2B(zoneKey)...)

	return append(resp, kcv...), nil
}
