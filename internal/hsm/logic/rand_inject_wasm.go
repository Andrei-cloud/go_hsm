//go:build wasm

package logic

import (
	"io"

	"github.com/andrei-cloud/go_hsm/pkg/pinblock"
)

// hostRandReader adapts the HSM host CSPRNG (randomKey, backed by the
// wasmRandomKey host import) to io.Reader for the pinblock package. WASM
// plugins are built without a goroutine scheduler, and TinyGo's crypto/rand
// fallback on wasip1 needs one, so pinblock.Rand must come from the host.
type hostRandReader struct{}

func (hostRandReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	key, err := randomKey(len(p))
	if err != nil {
		return 0, err
	}

	copy(p, key)

	return len(p), nil
}

var _ io.Reader = hostRandReader{}

func init() {
	pinblock.Rand = hostRandReader{}
}
