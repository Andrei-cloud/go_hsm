package main

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/andrei-cloud/go_hsm/internal/logging"
	"github.com/andrei-cloud/go_hsm/internal/plugins"
	"github.com/andrei-cloud/go_hsm/internal/server"
	"github.com/rs/zerolog/log"
)

// main initializes logging, plugins, and starts the HSM server.
func main() {
	// determine debug mode from environment variable.
	debugEnv := os.Getenv("DEBUG")
	debug, _ := strconv.ParseBool(debugEnv)

	// determine human-readable output mode from environment.
	humanStr := os.Getenv("HUMAN")
	human, _ := strconv.ParseBool(humanStr)
	logging.InitLogger(debug, human)

	// Use background context for plugin manager to prevent premature cancellation
	ctx := context.Background()
	pm := plugins.NewPluginManager(ctx)
	if err := pm.LoadAll("./commands"); err != nil {
		log.Fatal().Err(err).Msg("failed to load plugins")
	}

	srv, err := server.NewServer(":1500", pm)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize server")
	}

	// reload plugins on SIGHUP.
	reloadChan := make(chan os.Signal, 1)
	signal.Notify(reloadChan, syscall.SIGHUP)
	go func() {
		for range reloadChan {
			if err := pm.LoadAll("./commands"); err != nil {
				log.Error().Err(err).Msg("failed to reload plugins")
			} else {
				log.Info().Msg("plugins reloaded")
			}
		}
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

	os.Exit(0)
}
