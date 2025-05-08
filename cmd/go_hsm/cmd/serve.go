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
		// Use default LMK value if not provided.
		if lmk == "" {
			lmk = "0123456789ABCDEFFEDCBA9876543210"
		}

		// Notify starting server.
		fmt.Printf("starting HSM server on port %s\n", port)

		// Initialize logger.
		logging.InitLogger(debug, human)

		// Initialize the HSM instance.
		hsmInstance, err := hsm.NewHSM(lmk, hsm.FirmwareVersion)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to initialize HSM instance: %v\n", err)
			os.Exit(1)
		}

		// Initialize the PluginManager with the HSM instance.
		pluginManager := plugins.NewPluginManager(
			cmd.Context(),
			hsmInstance,
		)

		// Load plugins from the specified directory.
		pluginDir := "./commands"
		if err := pluginManager.LoadAll(pluginDir); err != nil {
			fmt.Fprintf(os.Stderr, "failed to load plugins: %v\n", err)
			os.Exit(1)
		}

		// Initialize the server.
		srv, err := server.NewServer(port, pluginManager)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to initialize server: %v\n", err)
			os.Exit(1)
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
					fmt.Fprintf(os.Stderr, "failed to reload plugins: %v\n", err)
				} else {
					srv.SetPluginManager(newPM)
					fmt.Println("plugins reloaded")
				}
			}
		}()

		// Ensure all goroutines exit when the program quits.
		defer func() {
			signal.Stop(reloadChan)
		}()

		if err := srv.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to start server: %v\n", err)
			os.Exit(1)
		}

		// wait for shutdown signal.
		stopChan := make(chan os.Signal, 1)
		signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)
		sig := <-stopChan
		fmt.Printf("signal %v received, shutting down server\n", sig)

		if err := srv.Stop(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to stop server: %v\n", err)
		}

		fmt.Println("server stopped gracefully")
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().StringVarP(&port, "port", "p", ":1500", "Server port")
	serveCmd.Flags().StringVar(&lmk, "lmk", "", "LMK hex value")
	serveCmd.Flags().BoolVar(&debug, "debug", false, "Enable debug logging")
	serveCmd.Flags().BoolVar(&human, "human", false, "Enable human-readable logs")
}
