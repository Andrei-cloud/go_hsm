package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
)

type pluginInfo struct {
	name        string
	version     string
	description string
	author      string
}

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List installed plugins",
	Long:  `List all installed HSM command plugins with their metadata.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Try development mode first (running with go run)
		var projectRoot string
		paths := []string{
			".",        // Current directory
			"..",       // One level up
			"../..",    // Two levels up
			"../../..", // Three levels up
		}

		for _, path := range paths {
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				if absPath, err := filepath.Abs(path); err == nil {
					projectRoot = absPath
					break
				}
			}
		}

		// Fallback to binary location if not in development mode
		if projectRoot == "" {
			exePath, err := os.Executable()
			if err != nil {
				return fmt.Errorf("failed to get executable path: %w", err)
			}
			projectRoot = filepath.Dir(filepath.Dir(filepath.Dir(filepath.Dir(exePath))))
		}

		// Set up paths relative to project root
		pluginDir := filepath.Join(projectRoot, "plugins")

		// Create tabwriter for aligned output
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
		fmt.Fprintln(w, "Command\tDescription\tVersion\tAuthor")
		fmt.Fprintln(w, "-------\t-----------\t-------\t------")

		// Get all .wasm files
		files, err := filepath.Glob(filepath.Join(pluginDir, "*.wasm"))
		if err != nil {
			return fmt.Errorf("failed to list plugins: %w", err)
		}

		// Read metadata from each plugin
		for _, f := range files {
			// Get command name from filename
			name := strings.TrimSuffix(filepath.Base(f), ".wasm")

			// Get metadata from gen.go file since it's easier than parsing WASM
			genFile := filepath.Join(projectRoot, "internal", "commands", "plugins", name, "gen.go")
			content, err := os.ReadFile(genFile)
			if err != nil {
				continue // Skip if we can't read the file
			}

			info := pluginInfo{
				name:        name,
				version:     extractFlag(string(content), "version"),
				description: extractFlag(string(content), "desc"),
				author:      extractFlag(string(content), "author"),
			}

			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				info.name,
				info.description,
				info.version,
				info.author)
		}

		return w.Flush()
	},
}

func init() {
	pluginCmd.AddCommand(listCmd)
}

func extractFlag(content, flag string) string {
	lines := strings.Split(content, "\n")
	for _, line := range lines {
		// Try with quotes first
		quotedFlag := "-" + flag + "=\""
		if idx := strings.Index(line, quotedFlag); idx >= 0 {
			start := idx + len(quotedFlag)
			if end := strings.Index(line[start:], "\""); end >= 0 {
				value := line[start : start+end]
				if flag == "desc" && strings.Contains(value, "\" -") {
					value = value[:strings.Index(value, "\" -")]
				}
				return value
			}
		}

		// Try without quotes
		unquotedFlag := "-" + flag + "="
		if idx := strings.Index(line, unquotedFlag); idx >= 0 {
			start := idx + len(unquotedFlag)
			remaining := line[start:]
			// Find where the value ends (at space or end of line)
			end := strings.Index(remaining, " ")
			if end == -1 {
				// If no space found, take until end of line
				return remaining
			}
			return remaining[:end]
		}
	}

	return "Unknown"
}
