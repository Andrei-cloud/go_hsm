// Package plugins manages WASM plugin functionality.
package plugins

import "github.com/andrei-cloud/go_hsm/internal/hsm"

// PluginManager defines the interface for managing WASM plugins.
type PluginManagerInterface interface {
	// ExecuteCommand executes the given command with input via the corresponding WASM plugin.
	ExecuteCommand(cmd string, input []byte) ([]byte, error)

	// HSM returns the HSM instance used by this plugin manager.
	HSM() *hsm.HSM

	// Close closes the underlying WASM runtime and releases resources.
	Close() error
}
