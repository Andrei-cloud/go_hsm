// Package plugin provides plugin management commands.
package plugin

import "github.com/spf13/cobra"

// NewPluginCommand creates the main plugin command group.
func NewPluginCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Plugin management commands",
		Long:  `Commands for managing HSM command plugins.`,
	}

	// Add subcommands.
	cmd.AddCommand(NewCreateCommand())
	cmd.AddCommand(NewListCommand())

	return cmd
}
