// Package plugins manages WASM plugin functionality.
package plugins

import (
	"context"

	"github.com/andrei-cloud/go_hsm/internal/hsm"
)

// PluginManagerInterface defines the interface for managing WASM plugins.
type PluginManagerInterface interface {
	// ExecuteCommand executes the given command with input via the corresponding WASM plugin.
	ExecuteCommand(cmd string, input []byte) ([]byte, error)

	// ExecuteCommandWithContext executes a command via its WASM plugin, passing a context for logging.
	ExecuteCommandWithContext(ctx context.Context, cmd string, input []byte) ([]byte, error)

	// HSM returns the HSM instance used by this plugin manager.
	HSM() hsm.HSMInterface

	// Close closes the underlying WASM runtime and releases resources.
	Close() error

	// ListPlugins returns all loaded plugin names.
	ListPlugins() []string

	// GetPluginMetadata returns the metadata for a given plugin command.
	GetPluginMetadata(cmd string) (string, string, string)
}
