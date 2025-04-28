package logging

import (
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// InitLogger initializes the zerolog logger with the specified debug mode and output format.
func InitLogger(debug, human bool) {
	zerolog.TimeFieldFormat = time.RFC3339Nano
	// always initialize base logger with timestamp
	base := zerolog.New(os.Stdout).With().Timestamp().Logger()
	// select output format
	if human {
		log.Logger = base.Output(zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339Nano,
		})
	} else {
		log.Logger = base
	}
	// set global level based on debug flag
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}
