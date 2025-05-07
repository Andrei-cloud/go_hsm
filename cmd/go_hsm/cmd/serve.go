package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/andrei-cloud/go_hsm/internal/server"
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
	Run: func(cmd *cobra.Command, args []string) {
		// Initialize the server.
		srv, err := server.NewServer(port, nil) // Plugin manager is nil for now.
		if err != nil {
			log.Fatal().Err(err).Msg("failed to initialize server")
		}

		// Handle shutdown signals.
		stopChan := make(chan os.Signal, 1)
		signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)
		go func() {
			sig := <-stopChan
			log.Info().Msgf("signal %v received, shutting down server", sig)
			if err := srv.Stop(); err != nil {
				log.Error().Err(err).Msg("failed to stop server")
			}
			os.Exit(0)
		}()

		// Start the server.
		if err := srv.Start(); err != nil {
			log.Fatal().Err(err).Msg("failed to start server")
		}
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().StringVarP(&port, "port", "p", ":1500", "Server port")
	serveCmd.Flags().StringVar(&lmk, "lmk", "", "LMK hex value")
	serveCmd.Flags().BoolVar(&debug, "debug", false, "Enable debug logging")
	serveCmd.Flags().BoolVar(&human, "human", false, "Enable human-readable logs")
}
