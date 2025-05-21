package main

import (
	"os"

	"github.com/andrei-cloud/go_hsm/cmd/go_hsm/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
