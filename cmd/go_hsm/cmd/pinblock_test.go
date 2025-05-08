package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func executeCommand(root *cobra.Command, args ...string) (string, error) {
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)

	err := root.Execute()

	return buf.String(), err
}

func TestPinblockCommand_ListFormats(t *testing.T) {
	t.Parallel()

	output, err := executeCommand(rootCmd, "pinblock", "--list-formats")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if output == "" {
		t.Fatalf("expected output, got none")
	}
}

func TestPinblockCommand_MissingArguments(t *testing.T) {
	t.Parallel()

	_, err := executeCommand(rootCmd, "pinblock", "--pin", "1234")
	if err == nil {
		t.Fatalf("expected an error, got none")
	}
}

func TestPinblockCommand_ExtractMissingArguments(t *testing.T) {
	t.Parallel()

	// missing required flags for extraction
	_, err := executeCommand(rootCmd, "pinblock", "--extract", "--pinblock", "ABCDEF")
	if err == nil {
		t.Fatalf("expected an error for missing args, got none")
	}
}

func TestPinblockCommand_ExtractUnsupportedFormat(t *testing.T) {
	t.Parallel()

	// unsupported format code
	_, err := executeCommand(
		rootCmd,
		"pinblock",
		"--extract",
		"--pinblock",
		"ABCD1234EF567890",
		"--pan",
		"4111111111111111",
		"--format",
		"99",
	)
	if err == nil || !strings.Contains(err.Error(), "unknown thales pin block format code") {
		t.Fatalf("expected unknown format error, got %v", err)
	}
}
