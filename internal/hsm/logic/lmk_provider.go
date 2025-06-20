package logic

import (
	"log"

	"github.com/andrei-cloud/go_hsm/pkg/keyblocklmk"
	"github.com/andrei-cloud/go_hsm/pkg/variantlmk"
)

// load default variant LMK set once.
var defaultVariantSet = func() variantlmk.LMKSet {
	set, err := variantlmk.LoadDefaultLMKSet()
	if err != nil {
		log.Fatalf("failed to load default variant LMK set: %v", err)
	}
	return set
}()

// LMKEngine defines unified interface for variant and keyblock LMKs.
type LMKEngine interface {
	EncryptUnderLMK(key []byte, keyType string, schemeTag byte, lmkID string) ([]byte, error)
	DecryptUnderLMK(data []byte, keyType string, schemeTag byte, lmkID string) ([]byte, error)
}

// VariantLMKEngine implements LMKEngine using the existing variant LMK functions.
type VariantLMKProvider struct{}

// EncryptUnderLMK encrypts key under variant LMK, ignoring lmkID.
func (p VariantLMKProvider) EncryptUnderLMK(
	key []byte,
	keyType string,
	schemeTag byte,
	lmkID string,
) ([]byte, error) {
	return variantlmk.EncryptKeyUnderScheme(
		keyType,
		schemeTag,
		key,
		defaultVariantSet,
		false,
	)
}

// DecryptUnderLMK decrypts data under variant LMK, ignoring lmkID.
func (p VariantLMKProvider) DecryptUnderLMK(
	data []byte,
	keyType string,
	schemeTag byte,
	lmkID string,
) ([]byte, error) {
	return variantlmk.DecryptKeyUnderScheme(
		keyType,
		schemeTag,
		data,
		defaultVariantSet,
		false,
	)
}

// KeyBlockLMKProvider implements LMKEngine for key block LMK operations (wrap/unwrap).
// It will use the keyblocklmk package under the hood.
type KeyBlockLMKProvider struct {
	// lmk holds the AES-256 LMK for key block derivation and protection.
	lmk []byte
}

// EncryptUnderLMK encrypts clear key into a key block under the LMK.
func (p KeyBlockLMKProvider) EncryptUnderLMK(
	key []byte,
	keyType string,
	schemeTag byte,
	lmkID string,
) ([]byte, error) {
	// TODO: build a proper key block header from keyType and schemeTag.
	header := keyblocklmk.Header{
		Version:        'S',
		KeyUsage:       keyType,
		Algorithm:      'A', // placeholder for AES
		ModeOfUse:      'B', // default mode
		KeyVersionNum:  "00",
		Exportability:  'N',
		OptionalBlocks: 0,
		KeyContext:     '1',
	}
	return keyblocklmk.WrapKeyBlock(p.lmk, header, nil, key, 'S')
}

// DecryptUnderLMK unwraps a key block under the LMK and returns the clear key.
func (p KeyBlockLMKProvider) DecryptUnderLMK(
	data []byte,
	keyType string,
	schemeTag byte,
	lmkID string,
) ([]byte, error) {
	_, clear, err := keyblocklmk.UnwrapKeyBlock(p.lmk, data)
	return clear, err
}
