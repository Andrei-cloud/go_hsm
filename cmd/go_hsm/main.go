package main

import (
	"context"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/andrei-cloud/go_hsm/internal/hsm"
	"github.com/andrei-cloud/go_hsm/internal/logging"
	"github.com/andrei-cloud/go_hsm/internal/plugins"
	"github.com/andrei-cloud/go_hsm/internal/server"
	"github.com/rs/zerolog/log"
)

// main initializes logging, HSM, plugins, and starts the HSM server.
func main() {
	// determine debug mode from environment variable.
	debugEnv := os.Getenv("DEBUG")
	debug, _ := strconv.ParseBool(debugEnv)

	// determine human-readable output mode from environment.
	humanStr := os.Getenv("HUMAN")
	human, _ := strconv.ParseBool(humanStr)
	logging.InitLogger(debug, human)

	// Initialize HSM
	lmkHex := os.Getenv("HSM_LMK")
	if lmkHex == "" {
		log.Warn().Msg("HSM_LMK not set; using default LMK")
		lmkHex = "0123456789ABCDEFFEDCBA9876543210"
	}

	hsmSvc, err := hsm.NewHSM(lmkHex, "0007-E000")
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize HSM service")
	}

	// Use background context for plugin manager to prevent premature cancellation
	ctx := context.Background()
	pm := plugins.NewPluginManager(ctx, hsmSvc)
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
		// replace reload loop to atomically swap plugin manager on SIGHUP.
		for range reloadChan {
			newPM := plugins.NewPluginManager(ctx, hsmSvc)
			if err := newPM.LoadAll("./commands"); err != nil {
				log.Error().Err(err).Msg("failed to reload plugins")
			} else {
				srv.SetPluginManager(newPM)
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
