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

	return cmd
}

// resolveServerAddr returns the host and port to serve on; explicitly set
// CLI flags take precedence over configuration values. The flags are read
// from the command, not viper: config.Get() is populated by the config
// package's own viper instance, so flags bound to the global viper never
// reached it and were silently ignored.
func resolveServerAddr(cmd *cobra.Command, cfg *config.Config) (string, int, error) {
	host, port := cfg.Server.Host, cfg.Server.Port

	if cmd.Flags().Changed("host") {
		flagHost, err := cmd.Flags().GetString("host")
		if err != nil {
			return "", 0, fmt.Errorf("invalid --host flag: %w", err)
		}

		host = flagHost
	}

	if cmd.Flags().Changed("port") {
		flagPort, err := cmd.Flags().GetInt("port")
		if err != nil {
			return "", 0, fmt.Errorf("invalid --port flag: %w", err)
		}

		port = flagPort
	}

	return host, port, nil
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

	// Create root lifecycle context
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	// Initialize the PluginManager with HSM instance and configuration.
	pluginManager := plugins.NewPluginManager(
		ctx,
		hsmInstance,
		plugins.WithExecutionTimeout(cfg.Plugin.ExecutionTimeout),
		plugins.WithPoolSize(cfg.Plugin.PoolSize),
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

	// Initialize the server with host and port; CLI flags override config.
	host, port, err := resolveServerAddr(cmd, cfg)
	if err != nil {
		return err
	}

	serverAddr := fmt.Sprintf("%s:%d", host, port)
	srv, err := server.NewServer(
		serverAddr,
		pluginManager,
		server.WithConfig(cfg),
		server.WithServerContext(ctx),
	)
	if err != nil {
		return fmt.Errorf("failed to initialize server: %v", err)
	}

	// Reload plugins on SIGHUP.
	reloadChan := make(chan os.Signal, 1)
	signal.Notify(reloadChan, syscall.SIGHUP)
	defer signal.Stop(reloadChan)

	go func() {
		for range reloadChan {
			log.Info().Msg("reloading plugins...")

			// Create new plugin manager.
			newPM := plugins.NewPluginManager(
				ctx,
				hsmInstance,
				plugins.WithExecutionTimeout(cfg.Plugin.ExecutionTimeout),
				plugins.WithPoolSize(cfg.Plugin.PoolSize),
			)
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

	// Register stop signals BEFORE starting server to avoid race conditions.
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(stopChan)

	// Start the server. anet's Start() binds the listener and spawns the
	// accept loop, returning as soon as the port is bound; serving continues
	// in the background until Stop is called.
	if err := srv.Start(); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	select {
	case sig := <-stopChan:
		log.Info().Str("signal", sig.String()).Msg("shutting down server...")
	case <-ctx.Done():
		log.Info().Msg("context canceled, shutting down server...")
	}

	if err := srv.Stop(); err != nil {
		log.Error().Err(err).Msg("error during server shutdown")
	}

	_ = pluginManager.Close()

	return nil
}
