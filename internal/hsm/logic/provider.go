package logic

var LMKProviderInstance LMKProvider

type LMKProvider struct {
	EncryptUnderLMK func(plainKey []byte, keyType string, schemeTag byte) ([]byte, error)
	DecryptUnderLMK func(encryptedKey []byte, keyType string, schemeTag byte) ([]byte, error)
	RandomKey       func(length int) ([]byte, error)
}

func SetDefaultLMKProvider() {
	LMKProviderInstance = LMKProvider{
		EncryptUnderLMK: encryptUnderLMK,
		DecryptUnderLMK: decryptUnderLMK,
		RandomKey:       randomKey,
	}
}
