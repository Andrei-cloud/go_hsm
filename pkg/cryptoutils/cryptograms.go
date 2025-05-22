package cryptoutils

import (
	"crypto/cipher"
	"crypto/des"
	"slices"
)

// GenerateARQC10 computes the 8-byte ARQC per Visa CVN10 algorithm.
// sessionKey is the ICC Master Key for AC (16-byte DES3 key).
// data is the concatenated tag data in the proper order.
// Uses ISO7816-4 padding and DES3-CBC with zero IV.
func GenerateARQC10(issMKAC []byte, pan, psn string, data []byte) ([]byte, error) {
	iccMKAC, err := DeriveICCKey(issMKAC, pan, psn, "A")
	if err != nil {
		return nil, err
	}

	padded := padISO7816_4(data, des.BlockSize)
	cipherBlock, err := des.NewTripleDESCipher(iccMKAC)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, des.BlockSize)
	mode := cipher.NewCBCEncrypter(cipherBlock, iv)
	out := make([]byte, len(padded))
	mode.CryptBlocks(out, padded)

	return out[len(out)-des.BlockSize:], nil
}

// GenerateARPC10 computes the 8-byte ARPC per Visa CVN10 (Method 1).
func GenerateARPC10(issMKAC, arqc, arpcRc []byte, pan, psn string) ([]byte, error) {
	iccMKAC, err := DeriveICCKey(issMKAC, pan, psn, "A")
	if err != nil {
		return nil, err
	}

	msg := slices.Concat(arqc, arpcRc)
	// ISO9797-1 Algorithm 3: CBC-DES3 then single-DES decrypt/encrypt
	return MAC8(msg, iccMKAC, des.BlockSize, 3)
}

// GenerateARQC18 implements Visa CVN-18 ARQC calculation.
// issMKAC: 16-byte Issuer Master Key for AC (DES key)
// pan, psn: ASCII PAN and PSN used for ICC MK derivation
// atc: 2-byte application transaction counter
// data: concatenated tag data in EMV order (9F02..9F10).
func GenerateARQC18(
	issMKAC []byte,
	pan, psn string,
	atc []byte,
	data []byte,
) ([]byte, error) {
	// 1. derive ICC Master Key AC (Option B)
	iccMKAC, err := DeriveICCKey(issMKAC, pan, psn, "B")
	if err != nil {
		return nil, err
	}
	// 2. derive session key: common method (ATC||00..00)
	divers := slices.Concat(atc, make([]byte, 6)) // 8-byte block
	skAC, err := DeriveSessionKey(iccMKAC, divers)
	if err != nil {
		return nil, err
	}
	// 3. pad data to 8-byte boundary
	padded := padISO7816_4(data, des.BlockSize)

	// 4. 3DES-CBC with zero IV
	cipherBlock, err := des.NewTripleDESCipher(skAC)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, des.BlockSize)
	mode := cipher.NewCBCEncrypter(cipherBlock, iv)
	out := make([]byte, len(padded))
	mode.CryptBlocks(out, padded)

	// 5. ARQC = final 8 bytes
	return out[len(out)-des.BlockSize:], nil
}

// GenerateARPC18 implements Visa CVN-18 ARPC (method 2).
// issMKAC: 16-byte Issuer Master Key for AC (DES key)
// pan, psn: ASCII PAN and PSN used for ICC MK derivation
// atc: 2-byte application transaction counter
// arqc: 8-byte ARQC
// csu: 4-byte card status update
// propAuthData: optional 0–8 bytes Proprietary Authentication Data.
func GenerateARPC18(
	issMKAC []byte,
	pan, psn string,
	atc []byte,
	arqc, csu, propAuthData []byte,
) ([]byte, error) {
	// derive ICC MK AC
	iccMKAC, err := DeriveICCKey(issMKAC, pan, psn, "B")
	if err != nil {
		return nil, err
	}
	// derive session key
	divers := slices.Concat(atc, make([]byte, 6))
	skAC, err := DeriveSessionKey(iccMKAC, divers)
	if err != nil {
		return nil, err
	}
	// build message: ARQC || CSU || optional proprietary data
	msg := slices.Concat(arqc, csu)
	if len(propAuthData) > 0 {
		msg = slices.Concat(msg, propAuthData)
	}
	// pad
	padded := padISO7816_4(msg, des.BlockSize)
	// MAC Alg 3 (DES3-CBC then DES decrypt/encrypt)
	fullMac, err := MAC8(padded, skAC, des.BlockSize, 3)
	if err != nil {
		return nil, err
	}
	// ARPC = first 4 bytes
	return fullMac[:4], nil
}
