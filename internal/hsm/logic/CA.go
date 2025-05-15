// filepath: internal/hsm/logic/CA.go
package logic

import (
	"crypto/des"
	"encoding/hex"
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

// ExecuteCA translates a PIN block encrypted under a TPK to one encrypted under a ZPK or BDK under Variant LMK.
func ExecuteCA(input []byte) ([]byte, error) {
	data := input
	// Need at least src key scheme + key hex + dest key scheme + key hex + PIN block + 2 fmt codes.
	min := 1 + 16*2 + 1 + 16*2 + 16 + 2 + 2
	if len(data) < min {
		return nil, errorcodes.Err15
	}

	// Parse source TPK
	srcScheme := data[0]
	rawSrc := getKeyLength(srcScheme)
	hexSrc := rawSrc * 2
	if srcScheme != 'U' && srcScheme != 'T' && srcScheme != 'X' {
		return nil, errorcodes.Err15
	}
	if len(data) < 1+hexSrc {
		return nil, errorcodes.Err15
	}
	srcHex := string(data[1 : 1+hexSrc])
	data = data[1+hexSrc:]
	srcBytes, err := hex.DecodeString(srcHex)
	if err != nil {
		return nil, errorcodes.Err15
	}
	srcClear, err := decryptUnderLMK(srcBytes, "002", srcScheme)
	if err != nil {
		return nil, errorcodes.Err68
	}
	if !cryptoutils.CheckKeyParity(srcClear) {
		return nil, errorcodes.Err10
	}

	// Parse optional destination flag
	keyType := "001"
	if data[0] == '*' {
		keyType = "009"
		data = data[1:]
	} else if data[0] == '~' {
		keyType = "609"
		data = data[1:]
	}

	// Parse destination key
	dstScheme := data[0]
	rawDst := getKeyLength(dstScheme)
	hexDst := rawDst * 2
	if dstScheme != 'U' && dstScheme != 'T' && dstScheme != 'X' {
		return nil, errorcodes.Err15
	}
	if len(data) < 1+hexDst {
		return nil, errorcodes.Err15
	}
	dstHex := string(data[1 : 1+hexDst])
	data = data[1+hexDst:]
	dstBytes, err := hex.DecodeString(dstHex)
	if err != nil {
		return nil, errorcodes.Err15
	}
	dstClear, err := decryptUnderLMK(dstBytes, keyType, dstScheme)
	if err != nil {
		return nil, errorcodes.Err68
	}
	if !cryptoutils.CheckKeyParity(dstClear) {
		return nil, errorcodes.Err11
	}

	// Parse PIN block hex
	pinHex := string(data[:16])
	data = data[16:]

	// Parse and match format codes
	fmtSrc := string(data[:2])
	fmtDst := string(data[2:4])
	if fmtSrc != fmtDst {
		return nil, errorcodes.Err23
	}

	// Decrypt PIN block under source TPK
	inPin, err := hex.DecodeString(pinHex)
	if err != nil {
		return nil, errorcodes.Err15
	}
	srcCipher, err := des.NewTripleDESCipher(prepareTripleDESKey(srcClear))
	if err != nil {
		return nil, fmt.Errorf("tpk cipher: %w", err)
	}
	plain := make([]byte, len(inPin))
	srcCipher.Decrypt(plain, inPin)

	// Encrypt under destination key
	dstCipher, err := des.NewTripleDESCipher(prepareTripleDESKey(dstClear))
	if err != nil {
		return nil, fmt.Errorf("zpk cipher: %w", err)
	}
	out := make([]byte, len(plain))
	dstCipher.Encrypt(out, plain)

	// Build response: CB + 00 + PIN block + format
	resp := []byte("CB00")
	resp = append(resp, cryptoutils.Raw2B(out)...)
	resp = append(resp, fmtDst...)

	return resp, nil
}
