// Package server provides server-related CLI commands.
package server

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/andrei-cloud/go_hsm/internal/config"
	"github.com/andrei-cloud/go_hsm/internal/hsm"
	"github.com/andrei-cloud/go_hsm/internal/plugins"
	"github.com/andrei-cloud/go_hsm/internal/server"
	"github.com/andrei-cloud/go_hsm/pkg/common"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// NewServeCommand creates the serve command.
func NewServeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the HSM server",
		Long:  `Start the Hardware Security Module (HSM) server to process cryptographic commands over TCP.`,
		RunE:  runServe,
	}

	// Add serve command specific flags that can override config.
	cmd.Flags().String("host", "localhost", "Server host")
	cmd.Flags().Int("port", 1500, "Server port")

	// Bind serve command flags to viper.
	viper.BindPFlag("server.host", cmd.Flags().Lookup("host"))
	viper.BindPFlag("server.port", cmd.Flags().Lookup("port"))

	return cmd
}

func runServe(cmd *cobra.Command, _ []string) error {
	// Get configuration.
	cfg := config.Get()

	// Normalize log level and format from viper/config.
	logLevel := viper.GetString("log.level")
	logFormat := viper.GetString("log.format")
	logLevel = strings.TrimSpace(strings.ToLower(logLevel))
	logFormat = strings.TrimSpace(strings.ToLower(logFormat))

	// Initialize logger using config values (with CLI flags overriding config via viper).
	common.InitLogger(
		logLevel == "debug",
		logFormat == "human",
	)

	// Initialize the HSM instance.
	hsmInstance, err := hsm.NewHSM(hsm.FirmwareVersion, false)
	if err != nil {
		return fmt.Errorf("failed to initialize HSM instance: %v", err)
	}

	// Make sure plugin directory exists.
	if err := os.MkdirAll(cfg.Plugin.Path, 0o755); err != nil {
		return fmt.Errorf("failed to create plugin directory: %v", err)
	}

	// Initialize the PluginManager with HSM instance.
	pluginManager := plugins.NewPluginManager(
		cmd.Context(),
		hsmInstance,
	)

	// Load plugins from the configured directory.
	if err := pluginManager.LoadAll(cfg.Plugin.Path); err != nil {
		return fmt.Errorf("failed to load plugins: %v", err)
	}

	log.Debug().Msg("Loaded plugins metadata:")
	for _, cmdName := range pluginManager.ListPlugins() {
		version, description, author := pluginManager.GetPluginMetadata(cmdName)
		log.Debug().
			Str("command", cmdName).
			Str("version", version).
			Str("description", description).
			Str("author", author).
			Msg("plugin details")
	}

	// Initialize the server with configured host and port.
	serverAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv, err := server.NewServer(serverAddr, pluginManager)
	if err != nil {
		return fmt.Errorf("failed to initialize server: %v", err)
	}

	// Create a context that will be canceled when the server is stopping.
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	// Reload plugins on SIGHUP.
	reloadChan := make(chan os.Signal, 1)
	signal.Notify(reloadChan, syscall.SIGHUP)
	go func() {
		for range reloadChan {
			log.Info().Msg("reloading plugins...")

			// Create new plugin manager.
			newPM := plugins.NewPluginManager(ctx, hsmInstance)
			if err := newPM.LoadAll(cfg.Plugin.Path); err != nil {
				log.Error().Err(err).Msg("failed to reload plugins")
				continue
			}

			// Update server with new plugin manager.
			srv.SetPluginManager(newPM)
			log.Info().Msg("plugins reloaded")

			// Log reloaded plugin metadata in debug mode.
			log.Debug().Msg("Reloaded plugins metadata:")
			for _, cmdName := range newPM.ListPlugins() {
				version, description, author := newPM.GetPluginMetadata(cmdName)
				log.Debug().
					Str("command", cmdName).
					Str("version", version).
					Str("description", description).
					Str("author", author).
					Msg("plugin details")
			}
		}
	}()

	defer signal.Stop(reloadChan)

	if err := srv.Start(); err != nil {
		return fmt.Errorf("failed to start server: %v", err)
	}

	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	<-stopChan
	log.Info().Msg("shutting down server...")

	if err := srv.Stop(); err != nil {
		log.Error().Err(err).Msg("error during server shutdown")
	}

	return nil
}
