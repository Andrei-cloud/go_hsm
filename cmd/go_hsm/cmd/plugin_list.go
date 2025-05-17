package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/andrei-cloud/go_hsm/internal/hsm"
	"github.com/andrei-cloud/go_hsm/internal/plugins"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List installed plugins",
	Long:  `List all installed HSM command plugins with their metadata.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Disable logging for CLI commands
		log.Logger = log.Logger.Level(zerolog.Disabled)

		ctx := cmd.Context()

		// Try development mode first (running from source)
		pluginDir := "plugins"
		if _, err := os.Stat(pluginDir); err != nil {
			// Fallback to binary location
			exePath, err := os.Executable()
			if err != nil {
				return fmt.Errorf("failed to get executable path: %w", err)
			}
			pluginDir = filepath.Join(filepath.Dir(exePath), "plugins")
		}

		// Create tabwriter for aligned output
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "Command\tVersion\tDescription\tAuthor")
		fmt.Fprintln(w, "-------\t-------\t-----------\t------")

		// Create temporary HSM and plugin manager instances
		hsmInst, err := hsm.NewHSM(hsm.FirmwareVersion, false)
		if err != nil {
			return fmt.Errorf("failed to create HSM instance: %w", err)
		}

		pluginManager := plugins.NewPluginManager(ctx, hsmInst)
		defer pluginManager.Close()

		// Load all plugins
		if err := pluginManager.LoadAll(pluginDir); err != nil {
			return fmt.Errorf("failed to load plugins: %w", err)
		}

		// Get all loaded plugins and output their metadata
		for _, cmdName := range pluginManager.ListPlugins() {
			version, description, author := pluginManager.GetPluginMetadata(cmdName)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				cmdName,
				version,
				description,
				author)
		}

		return w.Flush()
	},
}

func init() {
	pluginCmd.AddCommand(listCmd)
}
