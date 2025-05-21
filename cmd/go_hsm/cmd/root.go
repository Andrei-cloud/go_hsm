// Package cmd provides the CLI commands for the go_hsm application.
package cmd

import (
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/config"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile string
	cfg     *config.Config
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "go_hsm",
	Short: "Hardware Security Module server and utilities",
	Long: `A flexible HSM server and utility tool for PIN block operations 
	and other cryptographic functions for payment card processing.`,
	SilenceErrors: true,
	SilenceUsage:  true,
	PersistentPreRunE: func(_ *cobra.Command, _ []string) error {
		// Initialize configuration before running any command
		if err := config.Initialize(); err != nil {
			return fmt.Errorf("failed to initialize configuration: %w", err)
		}
		cfg = config.Get()

		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Add persistent flags that affect all commands
	rootCmd.PersistentFlags().
		StringVar(&cfgFile, "config", "", "config file (default is $HOME/.go_hsm/config.yaml)")

	// Add global flags that can override config file settings
	rootCmd.PersistentFlags().
		String("log-level", "info", "logging level (debug, info, warn, error)")
	rootCmd.PersistentFlags().String("log-format", "", "logging format (human, json)")
	rootCmd.PersistentFlags().String("plugin-path", "plugins", "path to plugin directory")

	// Bind flags to viper
	viper.BindPFlag("log.level", rootCmd.PersistentFlags().Lookup("log-level"))
	viper.BindPFlag("log.format", rootCmd.PersistentFlags().Lookup("log-format"))
	viper.BindPFlag("plugin.path", rootCmd.PersistentFlags().Lookup("plugin-path"))
}
