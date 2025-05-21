package cmd

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

// pluginCmd represents the plugin command.
var pluginCmd = &cobra.Command{
	Use:   "plugin",
	Short: "Plugin management commands",
	Long:  `Commands for managing HSM command plugins.`,
}

// createCmd represents the create command.
var createCmd = &cobra.Command{
	Use:   "create NAME",
	Short: "Create a new plugin",
	Long: `Create a new HSM command plugin. This will:
1. Create the logic implementation file
2. Create the plugin stub
3. Generate the wrapper code
4. Build the WASM plugin`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		name := strings.ToUpper(args[0])

		// 1. Create the logic file
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

// Execute%s processes the %s command payload.
func Execute%s(input []byte) ([]byte, error) {
	logInfo("%s: Starting command processing.")

	if len(input) < 2 {
		return nil, errorcodes.Err15
	}

	// TODO: Implement command logic here
	
	return []byte("%s00"), nil
}`, name, name, name, name, incrementCommandCode(name))

		testContent := fmt.Sprintf(`package logic

import (
	"testing"

	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
)

func TestExecute%s(t *testing.T) {
	t.Parallel()

	testCases := []struct {
		name             string
		input            []byte
		expectedResponse []byte
		expectedError    error
	}{
		{
			name:             "Short Input",
			input:            []byte{1},
			expectedResponse: nil,
			expectedError:    errorcodes.Err15,
		},
		// TODO: Add more test cases
	}

	for _, tc := range testCases {
		tc := tc // Capture range variable
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			resp, err := Execute%s(tc.input)

			if err != tc.expectedError {
				t.Errorf("expected error %%v, got %%v", tc.expectedError, err)
			}

			if err == nil {
				if string(resp[:4]) != "%s00" {
					t.Errorf("expected prefix %s00, got %%s", string(resp[:4]))
				}
			}
		})
	}
}`, name, name, incrementCommandCode(name), incrementCommandCode(name))

		if err := os.WriteFile(logicPath, []byte(logicContent), 0o644); err != nil {
			return fmt.Errorf("failed to create logic file: %w", err)
		}

		if err := os.WriteFile(testPath, []byte(testContent), 0o644); err != nil {
			return fmt.Errorf("failed to create test file: %w", err)
		}

		// 2. Create the plugin stub directory and gen.go
		pluginDir := filepath.Join("internal", "commands", "plugins", name)
		if err := os.MkdirAll(pluginDir, 0o755); err != nil {
			return fmt.Errorf("failed to create plugin directory: %w", err)
		}

		stubPath := filepath.Join(pluginDir, "gen.go")
		//nolint:lll // it is generated code
		stubContent := fmt.Sprintf(
			`//go:generate plugingen -cmd=%s -logic=github.com/andrei-cloud/go_hsm/internal/hsm/logic -version=%s -desc "%s" -author "%s" -out=.

package main`,
			name,
			pluginVersion,
			pluginDesc,
			pluginAuthor,
		)

		if err := os.WriteFile(stubPath, []byte(stubContent), 0o644); err != nil {
			return fmt.Errorf("failed to create stub file: %w", err)
		}

		// 3. Generate wrapper and build plugin
		cmd.Printf("Created plugin files for %s\n", name)
		cmd.Println("Running make gen to generate wrapper...")

		if err := runMake("gen"); err != nil {
			return fmt.Errorf("failed to generate wrapper: %w", err)
		}

		cmd.Println("Building WASM plugin...")
		if err := runMake("plugins", fmt.Sprintf("CMD=%s", name)); err != nil {
			return fmt.Errorf("failed to build plugin: %w", err)
		}

		cmd.Printf("Successfully created and built plugin %s\n", name)

		return nil
	},
}

func init() {
	rootCmd.AddCommand(pluginCmd)
	pluginCmd.AddCommand(createCmd)

	createCmd.Flags().StringVarP(&pluginDesc, "desc", "d", "", "Plugin description")
	createCmd.Flags().StringVarP(&pluginVersion, "version", "v", "0.1.0", "Plugin version")
	createCmd.Flags().StringVarP(&pluginAuthor, "author", "a", "HSM Team", "Plugin author")
}

func incrementCommandCode(cmd string) string {
	if len(cmd) < 2 {
		return cmd + "A"
	}
	last := cmd[1]
	if last == 'Z' {
		last = 'A'
	} else {
		last++
	}

	return string(cmd[0]) + string(last)
}

func runMake(target string, args ...string) error {
	makeCmd := exec.Command("make", append([]string{target}, args...)...)
	makeCmd.Stdout = os.Stdout
	makeCmd.Stderr = os.Stderr

	return makeCmd.Run()
}
