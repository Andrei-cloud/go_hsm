package cmd

import (
	"bytes"
	"testing"

	"github.com/spf13/cobra"
)

func executeCommand(root *cobra.Command, args ...string) (output string, err error) {
	buf := new(bytes.Buffer)
	root.SetOut(buf)
	root.SetErr(buf)
	root.SetArgs(args)

	err = root.Execute()
	return buf.String(), err
}

func TestPinblockCommand_ListFormats(t *testing.T) {
	output, err := executeCommand(rootCmd, "pinblock", "--list-formats")
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if len(output) == 0 {
		t.Fatalf("expected output, got none")
	}
}

func TestPinblockCommand_MissingArguments(t *testing.T) {
	_, err := executeCommand(rootCmd, "pinblock", "--pin", "1234")
	if err == nil {
		t.Fatalf("expected an error, got none")
	}
}
