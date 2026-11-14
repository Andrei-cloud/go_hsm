package logic

import (
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/moov-io/tr31/pkg/tr31"
)

const (
	// keyBlockScheme marks a key that travels as an ANSI X9 TR-31 key block
	// under the ZMK.
	keyBlockScheme = 'R'
	// keyBlockHeaderLength is the version letter and the four-digit length that
	// open every TR-31 block.
	keyBlockHeaderLength = 5
	// keyBlockFixedHeaderLength is a TR-31 header with no optional blocks,
	// the only kind sealKeyBlock makes.
	keyBlockFixedHeaderLength = 16
	// keyBlockVersion is the block version for a TDES ZMK: B, with key
	// derivation (version A is deprecated).
	keyBlockVersion = tr31.TR31_VERSION_B
)

// keyBlockUsageFor is the TR-31 key usage a key of keyType is sent with, and
// the usages a received block may carry to be taken in as keyType. It is a
// switch, not a package-level map: plugins are instantiated without running
// package initialisers, so a map TinyGo can't build at compile time would be
// empty there.
func keyBlockUsageFor(keyType string) (string, []string, bool) {
	switch keyType {
	case "000": // ZMK: key encryption or wrapping
		return "K0", []string{"K0"}, true
	case "001": // ZPK: PIN encryption
		return "P0", []string{"P0"}, true
	case "003", "008": // TAK, ZAK: MAC
		return "M3", []string{"M0", "M1", "M3"}, true
	default:
		return "", nil, false
	}
}

// modeOfUseFor is the mode of use a key with usage is sent with, and the modes
// a received block may carry: a MAC key generates and verifies (C), or only
// one of the two; a PIN or key-encryption key encrypts and decrypts (B), or
// only one of the two.
func modeOfUseFor(usage string) (string, []string) {
	if usage[0] == 'M' {
		return "C", []string{"C", "G", "V"}
	}

	return "B", []string{"B", "D", "E"}
}

// readKeyBlock reads a key block under the ZMK: 'R', then the block, whose
// length is its own characters 2 to 5. It returns the block and what follows.
func readKeyBlock(cmd string, data []byte) (string, []byte, error) {
	if len(data) < 1+keyBlockHeaderLength || data[0] != keyBlockScheme {
		logError(cmd + ": key block too short")
		return "", nil, errorcodes.Err83
	}

	length, err := strconv.Atoi(string(data[2 : 1+keyBlockHeaderLength]))
	if err != nil || length < keyBlockHeaderLength || len(data) < 1+length {
		logError(cmd + ": key block length doesn't hold")
		return "", nil, errorcodes.Err83
	}

	return string(data[1 : 1+length]), data[1+length:], nil
}

// openKeyBlock opens block under the clear ZMK and checks that it may be
// taken in as a key of keyType: its key usage, its algorithm and its mode of
// use. It returns the clear key.
func openKeyBlock(cmd string, zmk []byte, block, keyType string) ([]byte, error) {
	_, accept, ok := keyBlockUsageFor(keyType)
	if !ok {
		logError(cmd + ": key type can't travel in a key block")
		return nil, errorcodes.Err04
	}

	keyBlock, err := tr31.NewKeyBlock(zmk, nil)
	if err != nil {
		logError(cmd + ": ZMK can't open a key block")
		return nil, errorcodes.Err83
	}

	key, err := keyBlock.Unwrap(block)
	if err != nil {
		var blockErr *tr31.KeyBlockError
		if errors.As(err, &blockErr) && blockErr.Message == tr31.BlockErrorMacNotMatched {
			logError(cmd + ": key block authentication failure")
			return nil, errorcodes.ErrA4
		}

		logError(cmd + ": key block format error")
		return nil, errorcodes.Err83
	}

	header := keyBlock.GetHeader()
	if !slices.Contains(accept, header.KeyUsage) {
		logError(cmd + ": key block usage doesn't fit the key type")
		return nil, errorcodes.ErrA6
	}

	if header.Algorithm != tr31.ENC_ALGORITHM_TRIPLE_DES {
		logError(cmd + ": key block algorithm isn't TDES")
		return nil, errorcodes.ErrA7
	}

	if _, modes := modeOfUseFor(header.KeyUsage); !slices.Contains(modes, header.ModeOfUse) {
		logError(cmd + ": key block mode of use doesn't fit its usage")
		return nil, errorcodes.ErrA8
	}

	return key, nil
}

// sealKeyBlock wraps key, of keyType, in a TR-31 block under the clear ZMK,
// with the usage and mode of use its key type travels with, key version 00
// and no further export.
func sealKeyBlock(cmd string, zmk, key []byte, keyType string) (string, error) {
	usage, _, ok := keyBlockUsageFor(keyType)
	if !ok {
		logError(cmd + ": key type can't travel in a key block")
		return "", errorcodes.Err04
	}

	mode, _ := modeOfUseFor(usage)
	header, err := tr31.NewHeader(keyBlockVersion, usage, tr31.ENC_ALGORITHM_TRIPLE_DES, mode, "00", "N")
	if err != nil {
		logError(cmd + ": key block header")
		return "", errorcodes.ErrB2
	}

	keyBlock, err := tr31.NewKeyBlock(zmk, header)
	if err != nil {
		logError(cmd + ": ZMK can't seal a key block")
		return "", errorcodes.ErrB2
	}

	block, err := keyBlock.Wrap(key, nil)
	if err != nil {
		logError(cmd + ": key block wrap failed")
		return "", errorcodes.ErrB2
	}

	// The library writes the encrypted key and MAC in lower-case hex; HSMs and
	// the standard's examples send upper case, and a peer may compare it as text.
	return block[:keyBlockFixedHeaderLength] + strings.ToUpper(block[keyBlockFixedHeaderLength:]), nil
}
