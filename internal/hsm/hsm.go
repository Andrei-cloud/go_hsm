// Package hsm provides the HSM service implementation and key management.
package hsm

import (
	"errors"
	"fmt"

	"github.com/andrei-cloud/go_hsm/pkg/pinblock"
	"github.com/andrei-cloud/go_hsm/pkg/variantlmk"
)

// FirmwareVersion is the constant firmware version for the HSM.
const FirmwareVersion = "7000-E000"

// HSM represents the hardware security module server.
// It holds the Variant LMK set for scheme-based encryption,
// firmware version, and PCI compliance mode.
type HSM struct {
	VariantLmkSet   variantlmk.LMKSet
	PciMode         bool
	FirmwareVersion string
}

var errUnknownThalesPinBlockFormat = errors.New("unknown thales pin block format code")

// NewHSM creates a new HSM instance.
// firmwareVersion is the HSM firmware version string.
// pciMode determines which set of key type definitions to use for Variant LMK operations.
func NewHSM(firmwareVersion string, pciMode bool) (*HSM, error) {
	variantLmkSet, err := variantlmk.LoadDefaultLMKSet()
	if err != nil {
		return nil, fmt.Errorf("failed to load default variant lmk set: %w", err)
	}

	return &HSM{
		VariantLmkSet:   variantLmkSet,
		PciMode:         pciMode,
		FirmwareVersion: firmwareVersion,
	}, nil
}

// EncryptKeyWithVariantScheme encrypts key data under a variant LMK using a specific key type and scheme tag ('U' or 'T').
// keyData is the plaintext key to be encrypted (16 bytes for 'U', 24 bytes for 'T').
// keyTypeStr is the string representation of the key type (e.g., "001", "209").
// schemeTag is 'U' for double-length TDES keys or 'T' for triple-length TDES keys.
func (h *HSM) EncryptKeyWithVariantScheme(
	keyData []byte,
	keyTypeStr string,
	schemeTag byte,
) ([]byte, error) {
	if h == nil {
		return nil, fmt.Errorf("hsm instance is nil")
	}

	keyTypeDetails, err := variantlmk.GetKeyTypeDetails(keyTypeStr, h.PciMode)
	if err != nil {
		return nil, fmt.Errorf("failed to get key type details: %w", err)
	}

	if keyTypeDetails.LMKPair < 0 || keyTypeDetails.LMKPair >= len(h.VariantLmkSet) {
		return nil, fmt.Errorf(
			"invalid lmk pair index %d for key type %s",
			keyTypeDetails.LMKPair,
			keyTypeStr,
		)
	}
	baseLMKPair := h.VariantLmkSet[keyTypeDetails.LMKPair]

	// Apply the key-type specific variant to the LMK pair.
	keyTypeVariantedLMK, err := baseLMKPair.ApplyVariant(keyTypeDetails.VariantID)
	if err != nil {
		return nil, fmt.Errorf("failed to apply key type variant to lmk: %w", err)
	}

	// Encrypt the key data using the 'U' or 'T' scheme with the key-type-varianted LMK.
	encryptedKey, err := variantlmk.EncryptUnderVariantLMK(keyData, keyTypeVariantedLMK, schemeTag)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt key under variant lmk scheme: %w", err)
	}

	return encryptedKey, nil
}

// DecryptKeyWithVariantScheme decrypts key data that was encrypted under a variant LMK
// using a specific key type and scheme tag ('U' or 'T').
// encryptedKeyData is the ciphertext key to be decrypted.
// keyTypeStr is the string representation of the key type (e.g., "001", "209").
// schemeTag is 'U' for double-length TDES keys or 'T' for triple-length TDES keys.
func (h *HSM) DecryptKeyWithVariantScheme(
	encryptedKeyData []byte,
	keyTypeStr string,
	schemeTag byte,
) ([]byte, error) {
	if h == nil {
		return nil, fmt.Errorf("hsm instance is nil")
	}

	keyTypeDetails, err := variantlmk.GetKeyTypeDetails(keyTypeStr, h.PciMode)
	if err != nil {
		return nil, fmt.Errorf("failed to get key type details: %w", err)
	}

	if keyTypeDetails.LMKPair < 0 || keyTypeDetails.LMKPair >= len(h.VariantLmkSet) {
		return nil, fmt.Errorf(
			"invalid lmk pair index %d for key type %s",
			keyTypeDetails.LMKPair,
			keyTypeStr,
		)
	}
	baseLMKPair := h.VariantLmkSet[keyTypeDetails.LMKPair]

	// Apply the key-type specific variant to the LMK pair.
	keyTypeVariantedLMK, err := baseLMKPair.ApplyVariant(keyTypeDetails.VariantID)
	if err != nil {
		return nil, fmt.Errorf("failed to apply key type variant to lmk: %w", err)
	}

	// Decrypt the key data using the 'U' or 'T' scheme with the key-type-varianted LMK.
	decryptedKey, err := variantlmk.DecryptUnderVariantLMK(
		encryptedKeyData,
		keyTypeVariantedLMK,
		schemeTag,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt key under variant lmk scheme: %w", err)
	}

	return decryptedKey, nil
}

// GetPinBlockFormatFromThalesCode maps a Thales PIN block format code string
// to the corresponding pinblock.PinBlockFormat.
// The Thales codes are based on common interpretations of their documentation.
func GetPinBlockFormatFromThalesCode(thalesCode string) (pinblock.PinBlockFormat, error) {
	switch thalesCode {
	case "01": // Typically ISO 9564-1 Format 0.
		return pinblock.ISO0, nil
	case "02": // Docutel.
		return pinblock.DOCUTEL, nil
	case "03": // Diebold / IBM 3624.
		return pinblock.DIEBOLD, nil
	case "04": // PLUS Network.
		return pinblock.PLUSNETWORK, nil
	case "05": // Typically ISO 9564-1 Format 1.
		return pinblock.ISO1, nil
	case "34": // Typically ISO 9564-1 Format 2. (Decimal 34 from prompt).
		return pinblock.ISO2, nil
	case "35": // Mastercard Pay Now & Pay Later. (Decimal 35 from prompt).
		return pinblock.MASTERCARDPAYNOWPAYLATER, nil
	case "41": // Visa PIN-only change. (Decimal 41 from prompt).
		return pinblock.VISANEWPINONLY, nil
	case "42": // Visa old+new PIN change. (Decimal 42 from prompt).
		return pinblock.VISANEWOLDIN, nil
	case "47": // Typically ISO 9564-1 Format 3. (Decimal 47 from prompt).
		return pinblock.ISO3, nil
	case "48": // Typically ISO 9564-1 Format 4. (Decimal 48 from prompt).
		return pinblock.ISO4, nil
	default:
		// Return zero value for format and an error.
		return 0, fmt.Errorf("%w: %s", errUnknownThalesPinBlockFormat, thalesCode)
	}
}
