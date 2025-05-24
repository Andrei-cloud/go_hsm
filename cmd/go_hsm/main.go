package main

import (
	"fmt"
	"os"

	"github.com/andrei-cloud/go_hsm/internal/commands/cli"
)

func main() {
	rootCmd, err := cli.NewRootCommand()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error initializing CLI: %v\n", err)
		os.Exit(1)
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
