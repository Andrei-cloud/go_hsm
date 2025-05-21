package plugins

// HSMCommand defines the behavior of a WASM plugin command handler.
type HSMCommand interface {
	Execute(input []byte) ([]byte, error)
}
