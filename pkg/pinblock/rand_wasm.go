//go:build wasm

package pinblock

import "io"

// Rand is the random byte source used for PIN block padding. On the WASM
// guest it is assigned by the logic package's init from the HSM host
// CSPRNG import; reading crypto/rand directly is not possible in a
// scheduler-less WASM plugin. Code that links pinblock into other WASM
// targets must assign Rand before encoding PIN blocks.
var Rand io.Reader //nolint:gochecknoglobals // injectable: assigned by logic init
