// Package cmd provides the CLI commands for the go_hsm application.
package cmd

import (
	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands.
var rootCmd = &cobra.Command{
	Use:   "go_hsm",
	Short: "Hardware Security Module server and utilities",
	Long:  `A flexible HSM server and utility tool for PIN block operations and other cryptographic functions for payment card processing.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}
