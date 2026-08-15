package logic

import (
	"sync/atomic"
)

var (
	lmkProviderPtr atomic.Pointer[LMKProvider]
	// LMKProviderInstance provides thread-safe access to the active LMKProvider.
	LMKProviderInstance = lmkProviderProxy{}
)

func init() {
	SetDefaultLMKProvider()
}

type LMKProvider struct {
	EncryptUnderLMK func(plainKey []byte, keyType string, schemeTag byte) ([]byte, error)
	DecryptUnderLMK func(encryptedKey []byte, keyType string, schemeTag byte) ([]byte, error)
	RandomKey       func(length int) ([]byte, error)
}

type lmkProviderProxy struct{}

func (lmkProviderProxy) EncryptUnderLMK(plainKey []byte, keyType string, schemeTag byte) ([]byte, error) {
	p := GetLMKProvider()
	if p.EncryptUnderLMK != nil {
		return p.EncryptUnderLMK(plainKey, keyType, schemeTag)
	}
	return encryptUnderLMK(plainKey, keyType, schemeTag)
}

func (lmkProviderProxy) DecryptUnderLMK(encryptedKey []byte, keyType string, schemeTag byte) ([]byte, error) {
	p := GetLMKProvider()
	if p.DecryptUnderLMK != nil {
		return p.DecryptUnderLMK(encryptedKey, keyType, schemeTag)
	}
	return decryptUnderLMK(encryptedKey, keyType, schemeTag)
}

func (lmkProviderProxy) RandomKey(length int) ([]byte, error) {
	p := GetLMKProvider()
	if p.RandomKey != nil {
		return p.RandomKey(length)
	}
	return randomKey(length)
}

func GetLMKProvider() LMKProvider {
	p := lmkProviderPtr.Load()
	if p != nil {
		return *p
	}
	return LMKProvider{
		EncryptUnderLMK: encryptUnderLMK,
		DecryptUnderLMK: decryptUnderLMK,
		RandomKey:       randomKey,
	}
}

func SetLMKProvider(p LMKProvider) {
	lmkProviderPtr.Store(&p)
}

func SetDefaultLMKProvider() {
	SetLMKProvider(LMKProvider{
		EncryptUnderLMK: encryptUnderLMK,
		DecryptUnderLMK: decryptUnderLMK,
		RandomKey:       randomKey,
	})
}
