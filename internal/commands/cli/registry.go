// Package cli provides centralized command registration.
package cli

import (
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/commands/cli/keys"
	"github.com/andrei-cloud/go_hsm/internal/commands/cli/pb"
	"github.com/andrei-cloud/go_hsm/internal/commands/cli/plugin"
	"github.com/andrei-cloud/go_hsm/internal/commands/cli/server"
	"github.com/spf13/cobra"
)

// RegisterCommands registers all root commands.
func RegisterCommands(root *cobra.Command) error {
	// Root commands.
	root.AddCommand(keys.NewKeysCommand())

	pinblockCmd, err := pb.NewPinBlockCommand()
	if err != nil {
		return fmt.Errorf("failed to create pinblock command: %w", err)
	}
	root.AddCommand(pinblockCmd)

	root.AddCommand(server.NewServeCommand())
	root.AddCommand(plugin.NewPluginCommand())

	return nil
}
