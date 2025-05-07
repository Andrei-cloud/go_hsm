package cmd

import (
	"os"
	"os/signal"
	"sync"
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

		// Ensure the stop channel is closed only once.
		var stopOnce sync.Once
		stopChan := make(chan os.Signal, 1)
		signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			sig := <-stopChan
			log.Info().Msgf("signal %v received, shutting down server", sig)

			stopOnce.Do(func() {
				if err := srv.Stop(); err != nil {
					log.Error().Err(err).Msg("failed to stop server")
				}
				close(stopChan)
			})
		}()

		// Start the server.
		if err := srv.Start(); err != nil {
			log.Fatal().Err(err).Msg("failed to start server")
		}

		// Block the main goroutine to keep the server running until a termination signal is received.
		<-stopChan

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
