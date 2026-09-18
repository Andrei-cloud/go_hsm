//go:build !wasm

package pinblock

import crand "crypto/rand"

// Rand is the random byte source used for PIN block padding.
// On native targets it is crypto/rand. On the WASM guest build it is replaced
// at package init by the HSM host CSPRNG, because crypto/rand on wasip1
// without getrandom(2) falls back to os.File reads whose TinyGo deadline
// machinery requires a goroutine scheduler, which WASM plugins are built
// without (-scheduler=none).
var Rand = crand.Reader //nolint:gochecknoglobals // injectable: WASM guests replace at init
