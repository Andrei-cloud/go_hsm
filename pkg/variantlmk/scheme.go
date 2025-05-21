package variantlmk

import (
	"errors"
	"fmt"
)

// EncryptKeyUnderScheme encrypts inputKey under the correct LMK based on keyTypeCode and schemeTag.
// If isKeyComponent is true, an additional 0xFF variant is applied to the LMK after the key-type variant.
func EncryptKeyUnderScheme(
	keyTypeCode string,
	schemeTag byte,
	inputKey []byte,
	lmkSet LMKSet,
	isKeyComponent bool,
) ([]byte, error) {
	var kt KeyType
	var ok bool

	if GetPCIComplianceMode() {
		kt, ok = KeyTypesPCI[keyTypeCode]
	} else {
		kt, ok = KeyTypes[keyTypeCode]
	}

	if !ok {
		return nil, fmt.Errorf("unknown key type %s for current compliance mode", keyTypeCode)
	}
	lmkPair := lmkSet[kt.LMKPair]
	variantLMK, err := lmkPair.ApplyVariant(kt.VariantID)
	if err != nil {
		return nil, fmt.Errorf("apply variant to lmk: %w", err)
	}
	if isKeyComponent {
		if len(variantLMK.Left) == 0 {
			return nil, errors.New("lmk left part is empty cannot apply component variant")
		}
		variantLMK.Left[0] ^= 0xFF
	}

	encrypted, err := EncryptUnderVariantLMK(inputKey, variantLMK, schemeTag)
	if err != nil {
		return nil, fmt.Errorf("encrypt under variant lmk: %w", err)
	}

	return encrypted, nil
}

// DecryptKeyUnderScheme decrypts an encryptedKey using the LMK associated with keyTypeCode and schemeTag.
// If isKeyComponent is true, an additional 0xFF variant is applied to the LMK after the key-type variant.
func DecryptKeyUnderScheme(
	keyTypeCode string,
	schemeTag byte,
	encryptedKey []byte,
	lmkSet LMKSet,
	isKeyComponent bool,
) ([]byte, error) {
	var kt KeyType
	var ok bool

	if GetPCIComplianceMode() {
		kt, ok = KeyTypesPCI[keyTypeCode]
	} else {
		kt, ok = KeyTypes[keyTypeCode]
	}

	if !ok {
		return nil, fmt.Errorf("unknown key type %s for current compliance mode", keyTypeCode)
	}

	lmkPair := lmkSet[kt.LMKPair]
	variantLMK, err := lmkPair.ApplyVariant(kt.VariantID)
	if err != nil {
		return nil, fmt.Errorf("apply variant to lmk: %w", err)
	}

	if isKeyComponent {
		if len(variantLMK.Left) == 0 {
			return nil, errors.New("lmk left part is empty cannot apply component variant")
		}
		variantLMK.Left[0] ^= 0xFF
	}

	decrypted, err := DecryptUnderVariantLMK(encryptedKey, variantLMK, schemeTag)
	if err != nil {
		return nil, fmt.Errorf("decrypt under variant lmk: %w", err)
	}

	return decrypted, nil
}
