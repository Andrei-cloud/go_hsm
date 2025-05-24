// Package plugin provides plugin creation commands.
package plugin

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	pluginDesc    string
	pluginVersion string
	pluginAuthor  string
)

// NewCreateCommand creates the create command.
func NewCreateCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create NAME",
		Short: "Create a new plugin",
		Long: `Create a new HSM command plugin. This will:
1. Create the logic implementation file
2. Create the plugin stub
3. Generate the wrapper code
4. Build the WASM plugin`,
		Args: cobra.ExactArgs(1),
		RunE: runCreatePlugin,
	}

	// Add flags.
	cmd.Flags().StringVarP(&pluginDesc, "desc", "d", "", "Plugin description")
	cmd.Flags().StringVarP(&pluginVersion, "version", "v", "0.1.0", "Plugin version")
	cmd.Flags().StringVarP(&pluginAuthor, "author", "a", "HSM Team", "Plugin author")

	return cmd
}

func runCreatePlugin(cmd *cobra.Command, args []string) error {
	name := strings.ToUpper(args[0])

	// 1. Create the logic file.
	logicDir := "internal/hsm/logic"
	if err := os.MkdirAll(logicDir, 0o755); err != nil {
		return fmt.Errorf("failed to create logic directory: %w", err)
	}

	logicPath := filepath.Join(logicDir, name+".go")
	testPath := filepath.Join(logicDir, name+"_test.go")

	logicContent := fmt.Sprintf(`package logic

import (
	"fmt"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
)

// Execute%s implements the %s HSM command.
func Execute%s(input []byte) ([]byte, error) {
	logInfo("%s: Starting command execution.")
	logDebug(fmt.Sprintf("%s: Input length: %%d, hex: %%x", len(input), input))

	// TODO: Implement %s command logic.
	logError("%s: Command not implemented")
	return nil, errorcodes.Err76 // Function not permitted.
}
`, name, name, name, name, name, name, name)

	testContent := fmt.Sprintf(`package logic

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExecute%s(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected []byte
		wantErr  bool
	}{
		{
			name:    "empty input",
			input:   []byte{},
			wantErr: true,
		},
		// TODO: Add more test cases.
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Execute%s(tt.input)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.expected, result)
		})
	}
}
`, name, name)

	if err := os.WriteFile(logicPath, []byte(logicContent), 0o644); err != nil {
		return fmt.Errorf("failed to create logic file: %w", err)
	}

	if err := os.WriteFile(testPath, []byte(testContent), 0o644); err != nil {
		return fmt.Errorf("failed to create test file: %w", err)
	}

	// 2. Create the plugin stub directory and gen.go.
	pluginDir := filepath.Join("internal", "commands", "plugins", name)
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		return fmt.Errorf("failed to create plugin directory: %w", err)
	}

	stubPath := filepath.Join(pluginDir, "gen.go")
	//nolint:lll // it is generated code
	stubContent := fmt.Sprintf(
		`//go:generate plugingen -cmd=%s -logic=github.com/andrei-cloud/go_hsm/internal/hsm/logic -version=%s -desc "%s" -author "%s" -out=.
package main
`,
		name,
		pluginVersion,
		pluginDesc,
		pluginAuthor,
	)

	if err := os.WriteFile(stubPath, []byte(stubContent), 0o644); err != nil {
		return fmt.Errorf("failed to create plugin stub: %w", err)
	}

	// 3. Generate the wrapper.
	if err := runMake("gen", "CMD="+name); err != nil {
		return fmt.Errorf("failed to generate plugin wrapper: %w", err)
	}

	// 4. Build the plugin.
	if err := runMake("plugins", "CMD="+name); err != nil {
		return fmt.Errorf("failed to build plugin: %w", err)
	}

	cmd.Printf("Successfully created and built plugin %s\n", name)

	return nil
}

func runMake(target string, args ...string) error {
	makeCmd := exec.Command("make", append([]string{target}, args...)...)
	makeCmd.Stdout = os.Stdout
	makeCmd.Stderr = os.Stderr

	return makeCmd.Run()
}
