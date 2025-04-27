package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/andrei-cloud/go_hsm/internal/logging"
	"github.com/andrei-cloud/go_hsm/internal/plugins"
	"github.com/andrei-cloud/go_hsm/internal/server"
	"github.com/rs/zerolog/log"
)

// main initializes logging, plugins, and starts the HSM server.
func main() {
	logging.InitLogger(true)

	pm := plugins.NewPluginManager(context.Background())
	if err := pm.LoadAll("./commands"); err != nil {
		panic(err)
	}

	srv, err := server.NewServer(":9999", pm)
	if err != nil {
		panic(err)
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

	// shutdown server on SIGINT or SIGTERM.
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-stopChan
		if err := srv.Stop(); err != nil {
			log.Error().Err(err).Msg("failed to stop server")
		}
		os.Exit(0)
	}()

	if err := srv.Start(); err != nil {
		panic(err)
	}
}
