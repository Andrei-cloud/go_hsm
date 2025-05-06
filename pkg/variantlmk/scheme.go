package variantlmk

import "fmt"

// EncryptKeyUnderScheme encrypts inputKey under the correct LMK based on keyTypeCode and schemeTag.
func EncryptKeyUnderScheme(
	keyTypeCode string,
	schemeTag byte,
	inputKey []byte,
	lmkSet LMKSet,
) ([]byte, error) {
	kt, ok := KeyTypes[keyTypeCode]
	if !ok {
		return nil, fmt.Errorf("unknown key type %s", keyTypeCode)
	}
	lmkPair := lmkSet[kt.LMKPair]
	variantLMK, err := lmkPair.ApplyVariant(kt.VariantID)
	if err != nil {
		return nil, fmt.Errorf("apply variant to lmk: %w", err)
	}
	encrypted, err := EncryptUnderVariantLMK(inputKey, variantLMK, schemeTag)
	if err != nil {
		return nil, fmt.Errorf("encrypt under variant lmk: %w", err)
	}

	return encrypted, nil
}
