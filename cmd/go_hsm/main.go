package main

import (
	"fmt"
	"os"

	"github.com/andrei-cloud/go_hsm/cmd/go_hsm/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
