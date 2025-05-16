package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/andrei-cloud/go_hsm/internal/hsm"
	"github.com/andrei-cloud/go_hsm/internal/logging"
	"github.com/andrei-cloud/go_hsm/internal/plugins"
	"github.com/andrei-cloud/go_hsm/internal/server"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	port      string
	lmk       string
	debug     bool
	human     bool
	pluginDir string
)

// serveCmd represents the serve command.
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the HSM server",
	Long:  `Start the Hardware Security Module (HSM) server to process cryptographic commands over TCP.`,
	RunE: func(cmd *cobra.Command, _ []string) error {
		// Initialize logger.
		logging.InitLogger(debug, human)

		// Initialize the HSM instance.
		hsmInstance, err := hsm.NewHSM(hsm.FirmwareVersion, false)
		if err != nil {
			return fmt.Errorf("failed to initialize HSM instance: %v", err)
		}

		// Make sure plugin directory exists
		if err := os.MkdirAll(pluginDir, 0o755); err != nil {
			return fmt.Errorf("failed to create plugin directory: %v", err)
		}

		// Initialize the PluginManager with HSM instance.
		pluginManager := plugins.NewPluginManager(
			cmd.Context(),
			hsmInstance,
		)

		// Load plugins from the specified directory.
		if err := pluginManager.LoadAll(pluginDir); err != nil {
			return fmt.Errorf("failed to load plugins: %v", err)
		}

		// Initialize the server.
		srv, err := server.NewServer(port, pluginManager)
		if err != nil {
			return fmt.Errorf("failed to initialize server: %v", err)
		}

		// Create a context that will be canceled when the server is stopping.
		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()

		// reload plugins on SIGHUP.
		reloadChan := make(chan os.Signal, 1)
		signal.Notify(reloadChan, syscall.SIGHUP)
		go func() {
			for range reloadChan {
				newPM := plugins.NewPluginManager(ctx, hsmInstance)
				if err := newPM.LoadAll(pluginDir); err != nil {
					log.Error().Err(err).Msg("failed to reload plugins")
				} else {
					srv.SetPluginManager(newPM)
					log.Info().Msg("plugins reloaded")
				}
			}
		}()

		defer signal.Stop(reloadChan)

		if err := srv.Start(); err != nil {
			return fmt.Errorf("failed to start server: %v", err)
		}

		stopChan := make(chan os.Signal, 1)
		signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)
		sig := <-stopChan
		log.Info().
			Str("signal", sig.String()).
			Msg("shutting down server")

		if err := srv.Stop(); err != nil {
			log.Error().Err(err).Msg("error during shutdown")
			return err
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().StringVarP(&port, "port", "p", ":1500", "Server port")
	serveCmd.Flags().BoolVar(&debug, "debug", false, "Enable debug logging")
	serveCmd.Flags().BoolVar(&human, "human", false, "Enable human-readable logs")
	serveCmd.Flags().
		StringVar(&pluginDir, "plugin-dir", "./plugins", "Directory to load plugins from")
}
