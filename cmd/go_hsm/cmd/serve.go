package cmd

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/andrei-cloud/go_hsm/internal/hsm"
	"github.com/andrei-cloud/go_hsm/internal/plugins"
	"github.com/andrei-cloud/go_hsm/internal/server"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var (
	port  string
	lmk   string
	debug bool
	human bool
)

// serveCmd represents the serve command.
var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the HSM server",
	Long:  `Start the Hardware Security Module (HSM) server to process cryptographic commands over TCP.`,
	Run: func(cmd *cobra.Command, _ []string) {
		// Configure human-readable logging if the human flag is set.
		if human {
			log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
		}

		// Use default LMK value if not provided.
		if lmk == "" {
			lmk = "0123456789ABCDEFFEDCBA9876543210"
		}

		// Initialize the HSM instance.
		hsmInstance, err := hsm.NewHSM(lmk, hsm.FirmwareVersion)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to initialize HSM instance")
		}

		// Initialize the PluginManager with the HSM instance.
		pluginManager := plugins.NewPluginManager(
			cmd.Context(),
			hsmInstance,
		)

		// Load plugins from the specified directory.
		pluginDir := "./commands"
		if err := pluginManager.LoadAll(pluginDir); err != nil {
			log.Fatal().Err(err).Msg("failed to load plugins")
		}

		// Initialize the server.
		srv, err := server.NewServer(port, pluginManager)
		if err != nil {
			log.Fatal().Err(err).Msg("failed to initialize server")
		}

		// Separate SIGHUP handling from termination signals.
		sighupChan := make(chan os.Signal, 1)
		signal.Notify(sighupChan, syscall.SIGHUP)

		// Create a context that will be canceled when the server is stopping.
		ctx, cancel := context.WithCancel(cmd.Context())
		defer cancel()

		// Ensure sighupChan is continuously monitored and does not block.
		// reload plugins on SIGHUP.
		reloadChan := make(chan os.Signal, 1)
		signal.Notify(reloadChan, syscall.SIGHUP)
		go func() {
			// replace reload loop to atomically swap plugin manager on SIGHUP.
			for range reloadChan {
				newPM := plugins.NewPluginManager(ctx, hsmInstance)
				if err := newPM.LoadAll("./commands"); err != nil {
					log.Error().Err(err).Msg("failed to reload plugins")
				} else {
					srv.SetPluginManager(newPM)
					log.Info().Msg("plugins reloaded")
				}
			}
		}()

		// Ensure all goroutines exit when the program quits.
		defer func() {
			signal.Stop(reloadChan)
		}()

		if err := srv.Start(); err != nil {
			log.Fatal().Err(err).Msg("failed to start server")
		}

		// wait for shutdown signal.
		stopChan := make(chan os.Signal, 1)
		signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)
		sig := <-stopChan
		log.Info().Msgf("signal %v received, shutting down server", sig)

		if err := srv.Stop(); err != nil {
			log.Error().Err(err).Msg("failed to stop server")
		}

		log.Info().Msg("server stopped gracefully")
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().StringVarP(&port, "port", "p", ":1500", "Server port")
	serveCmd.Flags().StringVar(&lmk, "lmk", "", "LMK hex value")
	serveCmd.Flags().BoolVar(&debug, "debug", false, "Enable debug logging")
	serveCmd.Flags().BoolVar(&human, "human", false, "Enable human-readable logs")
}
