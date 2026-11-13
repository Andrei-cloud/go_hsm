package logic

import (
	"crypto/des"
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/pkg/cryptoutils"
)

const (
	macBlockSize     = 8    // DES block, in bytes
	macHeadLength    = 8    // mode, format, size, algorithm, padding, key type (3)
	macLengthDigits  = 4    // message length, in hex digits
	macPaddingMarker = 0x80 // ISO/IEC 9797-1 padding method 2
	macShortBytes    = 4    // MAC size 0: 8 hex digits
	macLongBytes     = 8    // MAC size 1: 16 hex digits
	retailAlgorithm  = 3    // ISO/IEC 9797-1 algorithm 3, as cryptoutils numbers it
)

// macRequest is the common head of the M6 (generate MAC) and M8 (verify MAC)
// commands, parsed and with the MAC key decrypted.
type macRequest struct {
	macBytes  int    // MAC size in bytes: 4 (8 hex) or 8 (16 hex)
	algorithm byte   // '1' ISO/IEC 9797-1 algorithm 1, '3' algorithm 3
	format    byte   // '0' binary, '1' hex
	padding   byte   // '0' none, '1' method 1, '2' method 2
	keyType   string // '003' TAK, '008' ZAK
	key       []byte // clear MAC key
	message   []byte // padded message
	rest      []byte // input after the message block
}

// parseMACRequest reads, in order: mode flag (1N), input format flag (1N),
// MAC size (1N), MAC algorithm (1N), padding method (1N), key type (3H),
// MAC key under LMK, message length (4H, bytes of the message block as sent)
// and the message block. Only mode 0, a message in a single block, is
// supported.
func parseMACRequest(cmd string, input []byte) (*macRequest, error) {
	req, err := parseMACFlags(cmd, input)
	if err != nil {
		return nil, err
	}

	data, err := req.readKey(cmd, input[macHeadLength:])
	if err != nil {
		return nil, err
	}

	if err := req.readMessage(cmd, data); err != nil {
		return nil, err
	}

	return req, nil
}

// parseMACFlags reads the one-character flags and the key type.
func parseMACFlags(cmd string, input []byte) (*macRequest, error) {
	if len(input) < macHeadLength {
		logError(cmd + ": input too short")
		return nil, errorcodes.Err15
	}

	req := &macRequest{
		macBytes:  0,
		algorithm: input[3],
		format:    input[1],
		padding:   input[4],
		keyType:   string(input[5:8]),
		key:       nil,
		message:   nil,
		rest:      nil,
	}

	switch {
	case input[0] != '0':
		logError(cmd + ": only mode 0 (single block) is supported")
		return nil, errorcodes.Err02
	case req.format != '0' && req.format != '1':
		logError(cmd + ": invalid input format flag")
		return nil, errorcodes.Err03
	case req.algorithm != '1' && req.algorithm != '3':
		logError(cmd + ": invalid MAC algorithm")
		return nil, errorcodes.Err04
	case req.padding != '0' && req.padding != '1' && req.padding != '2':
		logError(cmd + ": invalid padding method")
		return nil, errorcodes.Err09
	case req.keyType != "003" && req.keyType != "008": // TAK and ZAK are the MAC keys
		logError(cmd + ": invalid key type")
		return nil, errorcodes.Err05
	}

	size, err := macSizeOf(input[2])
	if err != nil {
		logError(cmd + ": invalid MAC size")
		return nil, err
	}

	req.macBytes = size

	return req, nil
}

// macSizeOf is the MAC size flag in bytes.
func macSizeOf(flag byte) (int, error) {
	switch flag {
	case '0':
		return macShortBytes, nil
	case '1':
		return macLongBytes, nil
	}

	return 0, errorcodes.Err15
}

// readKey reads and decrypts the MAC key, and returns what follows it.
func (r *macRequest) readKey(cmd string, data []byte) ([]byte, error) {
	scheme, encryptedKey, rest, err := readKeyUnderLMK(data)
	if err != nil {
		logError(cmd + ": invalid MAC key")
		return nil, err
	}

	clearKey, err := LMKProviderInstance.DecryptUnderLMK(encryptedKey, r.keyType, scheme)
	if err != nil {
		logError(cmd + ": MAC key decryption failed")
		return nil, errorcodes.Err68
	}

	if !cryptoutils.CheckKeyParity(clearKey) {
		logError(cmd + ": MAC key parity error")
		return nil, errorcodes.Err10
	}

	r.key = clearKey

	return rest, nil
}

// readMessage reads the message length and block, decodes and pads the message,
// and keeps what follows it.
func (r *macRequest) readMessage(cmd string, data []byte) error {
	if len(data) < macLengthDigits {
		logError(cmd + ": missing message length")
		return errorcodes.Err15
	}

	length, err := strconv.ParseUint(string(data[:macLengthDigits]), 16, 16)
	if err != nil || int(length) > len(data)-macLengthDigits {
		logError(cmd + ": invalid message length")
		return errorcodes.Err06
	}

	block := data[macLengthDigits : macLengthDigits+int(length)]
	r.rest = data[macLengthDigits+int(length):]

	message := block
	if r.format == '1' {
		message, err = hex.DecodeString(string(block))
		if err != nil {
			logError(cmd + ": message is not hex")
			return errorcodes.Err15
		}
	}

	r.message, err = pad(r.padding, message)
	if err != nil {
		logError(cmd + ": unpadded message is not a whole number of blocks")
		return err
	}

	return nil
}

// pad pads message by the padding method flag; an unpadded message must already
// be a whole number of blocks.
func pad(method byte, message []byte) ([]byte, error) {
	switch method {
	case '1':
		return padMethod1(message), nil
	case '2':
		return padMethod2(message), nil
	}

	if len(message) == 0 || len(message)%macBlockSize != 0 {
		return nil, errorcodes.Err06
	}

	return message, nil
}

// readKeyUnderLMK reads a variant-LMK key: 16 hex digits, or 'U' and 32, or
// 'T' and 48. It returns the scheme tag, the key bytes and what follows.
func readKeyUnderLMK(data []byte) (byte, []byte, []byte, error) {
	if len(data) == 0 {
		return 0, nil, nil, errorcodes.Err15
	}

	scheme := byte('Z')
	start := 0

	if data[0] == 'U' || data[0] == 'T' {
		scheme = data[0]
		start = 1
	}

	end := start + getKeyLength(scheme)*2
	if len(data) < end {
		return 0, nil, nil, errorcodes.Err15
	}

	key, err := hex.DecodeString(string(data[start:end]))
	if err != nil {
		return 0, nil, nil, errorcodes.Err15
	}

	return scheme, key, data[end:], nil
}

// padMethod1 is ISO/IEC 9797-1 padding method 1: zeros to a whole block, and
// one block of zeros for an empty message.
func padMethod1(message []byte) []byte {
	padded := append([]byte{}, message...)
	if len(padded) == 0 || len(padded)%macBlockSize != 0 {
		padded = append(padded, make([]byte, macBlockSize-len(padded)%macBlockSize)...)
	}

	return padded
}

// padMethod2 is ISO/IEC 9797-1 padding method 2: 0x80, then zeros to a whole
// block.
func padMethod2(message []byte) []byte {
	padded := append(append([]byte{}, message...), macPaddingMarker)
	if len(padded)%macBlockSize != 0 {
		padded = append(padded, make([]byte, macBlockSize-len(padded)%macBlockSize)...)
	}

	return padded
}

// mac computes the request's MAC. Algorithm 1 runs every block through the
// whole key (triple DES for a double- or triple-length key); algorithm 3, the
// retail MAC, chains under the key's first half and finishes the last block
// under the whole key.
func (r *macRequest) mac() ([]byte, error) {
	if r.algorithm == '3' {
		if len(r.key) != 2*macBlockSize {
			return nil, errorcodes.Err27
		}

		mac, err := cryptoutils.CalculateMAC(r.message, r.key, r.macBytes, retailAlgorithm)
		if err != nil {
			return nil, fmt.Errorf("retail mac: %w", err)
		}

		return mac, nil
	}

	block, err := des.NewTripleDESCipher(cryptoutils.PrepareTripleDESKey(r.key))
	if err != nil {
		return nil, fmt.Errorf("mac key: %w", err)
	}

	chain := make([]byte, macBlockSize)
	for i := 0; i < len(r.message); i += macBlockSize {
		for j := range chain {
			chain[j] ^= r.message[i+j]
		}

		block.Encrypt(chain, chain)
	}

	return chain[:r.macBytes], nil
}
