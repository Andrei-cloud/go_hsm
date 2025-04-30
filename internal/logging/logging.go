package logging

import (
	"encoding/hex"
	"os"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// InitLogger initializes the zerolog logger with the specified debug mode and output format.
func InitLogger(debug, human bool) {
	zerolog.TimeFieldFormat = time.RFC3339Nano                 // always initialize base logger with timestamp.
	base := zerolog.New(os.Stdout).With().Timestamp().Logger() // initialize base logger.
	if human {
		log.Logger = base.Output(zerolog.ConsoleWriter{
			Out:        os.Stdout,
			TimeFormat: time.RFC3339Nano,
		}) // select output format.
	} else {
		log.Logger = base // use JSON logger.
	}
	if debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel) // set debug level.
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel) // set info level.
	}
}

// LogRequest logs a received command with structured fields.
func LogRequest(
	clientIP string,
	command string,
	description string,
	requestData []byte,
	activeConns int,
) {
	hexReq := hex.EncodeToString(requestData)
	log.Info().
		Str("event", "request_received").
		Str("client_ip", clientIP).
		Str("command", command).
		Str("description", description).
		Str("request_hex", hexReq).
		Int("active_connections", activeConns).
		Msg("received command")
}

// LogResponse logs a sent response with structured fields.
func LogResponse(
	clientIP string,
	command string,
	responseCommand string,
	responseData []byte,
	errorCode int,
	activeConns int,
) {
	hexResp := hex.EncodeToString(responseData)
	log.Info().
		Str("event", "response_sent").
		Str("client_ip", clientIP).
		Str("command", command).
		Str("response_command", responseCommand).
		Str("response_hex", hexResp).
		Int("error_code", errorCode).
		Int("active_connections", activeConns).
		Msg("sent response")
}
