//go:build wasm

package logic

import (
	"errors"
	"io"

	"github.com/andrei-cloud/go_hsm/pkg/hsmplugin"
	"github.com/andrei-cloud/go_hsm/pkg/pinblock"
)

// hostRandReader adapts the HSM host CSPRNG (randomBytes, backed by the
// wasmRandomBytes host import) to io.Reader for the pinblock package. It
// doesn't use randomKey, which only gives 8, 16 or 24 bytes with DES parity.
// WASM plugins are built without a goroutine scheduler, and TinyGo's
// crypto/rand fallback on wasip1 needs one, so pinblock.Rand must come from
// the host.
type hostRandReader struct{}

// hostRandomBytesMax is the most the host gives in one RandomBytes call.
const hostRandomBytesMax = 4096

func (hostRandReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if len(p) > hostRandomBytesMax {
		p = p[:hostRandomBytesMax]
	}

	b, err := randomBytes(len(p))
	if err != nil {
		return 0, err
	}

	copy(p, b)

	return len(p), nil
}

var _ io.Reader = hostRandReader{}

// randomBytes asks the host for length bytes from its CSPRNG, with no key
// length rule and no DES parity applied.
func randomBytes(length int) ([]byte, error) {
	buf := wasmRandomBytes(uint32(length))
	if buf == 0 {
		return nil, errors.New("failed to read random bytes")
	}

	b := hsmplugin.Buffer(buf).ToBytes()
	if len(b) != length {
		return nil, errors.New("random bytes length mismatch")
	}

	return b, nil
}

func init() {
	pinblock.Rand = hostRandReader{}
}
