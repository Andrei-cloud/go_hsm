package logic

import (
	"encoding/hex"
	"fmt"
	"log"

	"github.com/andrei-cloud/go_hsm/pkg/keyblocklmk"
	"github.com/andrei-cloud/go_hsm/pkg/variantlmk"
)

const (
	LMKTypeVariant LMKType = iota
	LMKTypeKeyBlock
)

// LMKRegistry holds registered LMK engines by string ID.
var LMKRegistry = make(map[string]LMKEngine)

// load default variant LMK set once.
var defaultVariantSet = func() variantlmk.LMKSet {
	set, err := variantlmk.LoadDefaultLMKSet()
	if err != nil {
		panic(fmt.Sprintf("failed to load default variant LMK set: %v", err))
	}

	return set
}()

// LMKType represents the type of LMK: Variant or KeyBlock.
type LMKType int

// LMKEngine defines unified interface for variant and keyblock LMKs.
type LMKEngine interface {
	EncryptUnderLMK(key []byte, keyType string, schemeTag byte, lmkID string) ([]byte, error)
	DecryptUnderLMK(data []byte, keyType string, schemeTag byte, lmkID string) ([]byte, error)
	GetLMKType() LMKType
}

// VariantLMKProvider implements LMKEngine using the existing variant LMK functions.
type VariantLMKProvider struct{}

// KeyBlockLMKProvider implements LMKEngine for key block LMK operations (wrap/unwrap).
// It will use the keyblocklmk package under the hood.
type KeyBlockLMKProvider struct {
	// lmk holds the AES-256 LMK for key block derivation and protection.
	lmk []byte
}

// init registers default LMKs: variant under "00" and key block under "01".
func init() {
	RegisterVariantLMK("00")

	// Register default AES-256 key block LMK under ID "01".
	defaultHex := hex.EncodeToString(keyblocklmk.DefaultTestAESLMK)
	if err := RegisterKeyBlockLMK("01", defaultHex); err != nil {
		log.Fatalf("failed to register default key block LMK: %v", err)
	}
}

// EncryptUnderLMK encrypts key under variant LMK, ignoring lmkID.
func (p VariantLMKProvider) EncryptUnderLMK(
	key []byte,
	keyType string,
	schemeTag byte,
	_ string,
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
	_ string,
) ([]byte, error) {
	return variantlmk.DecryptKeyUnderScheme(
		keyType,
		schemeTag,
		data,
		defaultVariantSet,
		false,
	)
}

// GetLMKType for VariantLMKProvider.
func (p VariantLMKProvider) GetLMKType() LMKType {
	return LMKTypeVariant
}

// EncryptUnderLMK encrypts clear key into a key block under the LMK.
func (p KeyBlockLMKProvider) EncryptUnderLMK(
	key []byte,
	keyType string,
	_ byte,
	_ string,
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

	return keyblocklmk.WrapKeyBlock(p.lmk, header, nil, key)
}

// DecryptUnderLMK unwraps a key block under the LMK and returns the clear key.
func (p KeyBlockLMKProvider) DecryptUnderLMK(
	data []byte,
	_ string,
	_ byte,
	_ string,
) ([]byte, error) {
	_, clearKey, err := keyblocklmk.UnwrapKeyBlock(p.lmk, data)
	if err != nil {
		return nil, err
	}

	return clearKey, nil
}

// GetLMKType for KeyBlockLMKProvider.
func (p KeyBlockLMKProvider) GetLMKType() LMKType {
	return LMKTypeKeyBlock
}

// RegisterVariantLMK registers a variant LMK provider under the given ID.
func RegisterVariantLMK(id string) {
	LMKRegistry[id] = VariantLMKProvider{}
}

// RegisterKeyBlockLMK registers a key block LMK provider under the given ID
// using the provided LMK hex string.
func RegisterKeyBlockLMK(id, lmkHex string) error {
	lmk, err := hex.DecodeString(lmkHex)
	if err != nil {
		return fmt.Errorf("invalid key block LMK hex for id %s: %w", id, err)
	}

	if len(lmk) != 32 {
		return fmt.Errorf("key block LMK must be 32 bytes, got %d", len(lmk))
	}

	LMKRegistry[id] = KeyBlockLMKProvider{lmk: lmk}

	return nil
}
