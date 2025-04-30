package server

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	anetserver "github.com/andrei-cloud/anet/server"
	"github.com/andrei-cloud/go_hsm/internal/hsm"
	"github.com/andrei-cloud/go_hsm/internal/plugins"
	"github.com/rs/zerolog/log"
)

const firmware = "0007-0001"

// logAdapter implements anet.Logger using zerolog.
type logAdapter struct{}

// Server wraps the anet TCP server and HSM logic.
type Server struct {
	address       string
	srv           *anetserver.Server
	pluginManager *plugins.PluginManager
	hsmSvc        *hsm.HSM
	activeConns   int32
}

func (l logAdapter) Print(v ...any) {
	log.Info().Msg(fmt.Sprint(v...))
}

func (l logAdapter) Printf(format string, v ...any) {
	log.Info().Msgf(format, v...)
}

func (l logAdapter) Infof(format string, v ...any) {
	log.Info().Msgf(format, v...)
}

func (l logAdapter) Warnf(format string, v ...any) {
	log.Warn().Msgf(format, v...)
}

func (l logAdapter) Errorf(format string, v ...any) {
	log.Error().Msgf(format, v...)
}

// NewServer configures and returns the HSM server instance.
func NewServer(address string, pm *plugins.PluginManager) (*Server, error) {
	cfg := &anetserver.ServerConfig{
		MaxConns:        100,
		ReadTimeout:     30 * time.Second,
		WriteTimeout:    30 * time.Second,
		IdleTimeout:     60 * time.Second,
		ShutdownTimeout: 5 * time.Second,
		Logger:          logAdapter{},
	}

	s := &Server{address: address, pluginManager: pm}
	handler := anetserver.HandlerFunc(s.handle)
	srv, err := anetserver.NewServer(address, handler, cfg)
	if err != nil {
		return nil, fmt.Errorf("server setup failed: %w", err)
	}
	s.srv = srv

	return s, nil
}

// Start initializes HSM backend and begins listening for connections.
func (s *Server) Start() error {
	log.Info().Str("address", s.address).Msg("server started")

	lmkHex := os.Getenv("HSM_LMK")
	if lmkHex == "" {
		log.Warn().Msg("HSM_LMK not set; using default LMK")
		lmkHex = "0123456789ABCDEFFEDCBA9876543210"
	}

	if len(lmkHex) != 32 && len(lmkHex) != 48 {
		log.Fatal().Msg("invalid lmk length")
	}

	if len(firmware) != 9 || firmware[4] != '-' {
		log.Fatal().Msg("invalid firmware format")
	}

	hsmSvc, err := hsm.NewHSM(lmkHex, firmware)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize HSM service")
	}
	s.hsmSvc = hsmSvc

	return s.srv.Start()
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() error {
	return s.srv.Stop()
}

// formatData returns ascii string if all bytes are printable, else hex string.
func formatData(data []byte) string {
	for _, b := range data {
		if b < 32 || b > 126 {
			return hex.EncodeToString(data)
		}
	}

	return string(data)
}

// Enhanced error handling and logging for unknown commands and errors.
func (s *Server) handle(conn *anetserver.ServerConn, data []byte) ([]byte, error) {
	client := conn.Conn.RemoteAddr().String()
	atomic.AddInt32(&s.activeConns, 1)
	defer atomic.AddInt32(&s.activeConns, -1)

	start := time.Now()
	log.Debug().
		Str("event", "handle_start").
		Str("client_ip", client).
		Msg("starting request handling")

	if len(data) < 2 {
		log.Error().Str("client_ip", client).Msg("malformed request")
		return nil, errors.New("malformed request")
	}

	cmd := string(data[:2])
	origPayload := data[2:]
	reqStr := formatData(data)
	log.Info().
		Str("event", "request_received").
		Str("client_ip", client).
		Str("command", cmd).
		Str("request", reqStr).
		Int("active_connections", int(atomic.LoadInt32(&s.activeConns))).
		Msg("received command")

	// handle built-in A0 encryption under LMK.
	var resp []byte
	var execErr error
	if cmd == "A0" {
		encrypted, err2 := s.hsmSvc.EncryptUnderLMK(origPayload)
		if err2 != nil {
			resp = s.errorResponse(cmd)
		} else {
			resp = append([]byte(s.incrementCode(cmd)), encrypted...)
		}
	} else {
		// determine execution payload for plugin
		var execPayload []byte
		if cmd == "NC" {
			// pass LMK hex and firmware version.
			lmkHexStr := hex.EncodeToString(s.hsmSvc.LMK)
			log.Debug().
				Str("event", "lmk_hex").
				Str("client_ip", client).
				Str("lmk_hex", lmkHexStr).
				Msg("LMK hex for NC command")
			execPayload = []byte(lmkHexStr + s.hsmSvc.FirmwareVersion)
			log.Debug().
				Str("event", "payload_for_nc").
				Str("client_ip", client).
				Str("payload", formatData(execPayload)).
				Msg("payload for NC command")
		} else {
			execPayload = origPayload
		}

		// record plugin execution time.
		execStart := time.Now()
		resp, execErr = s.pluginManager.ExecuteCommand(cmd, execPayload)
		execDur := time.Since(execStart)
		log.Debug().
			Str("event", "command_executed").
			Str("client_ip", client).
			Str("command", cmd).
			Str("duration", execDur.String()).
			Msg("command execution complete")
	}

	if execErr != nil {
		if execErr.Error() == "unknown command" {
			resp = s.errorResponse(cmd)
			log.Warn().
				Str("event", "unknown_command").
				Str("client_ip", client).
				Str("command", cmd).
				Msg("Command not recognized, responding with error code")
		} else {
			log.Error().
				Str("event", "plugin_error").
				Str("client_ip", client).
				Str("command", cmd).
				Err(execErr).
				Msg("Plugin execution failed")
			resp = s.errorResponse(cmd)
		}
	}

	respStr := formatData(resp)
	log.Info().
		Str("event", "response_sent").
		Str("client_ip", client).
		Str("response", respStr).
		Int("active_connections", int(atomic.LoadInt32(&s.activeConns))).
		Msg("sent response")

	total := time.Since(start)
	log.Debug().
		Str("event", "handle_done").
		Str("request", reqStr).
		Str("response", respStr).
		Str("duration", total.String()).
		Msg("completed request handling")

	return resp, nil
}

// incrementCode returns the next command code by incrementing the second character.
func (s *Server) incrementCode(cmd string) string {
	b := []byte(cmd)
	if len(b) < 2 {
		return cmd
	}
	if b[1] == 'Z' {
		b[1] = 'A'
	} else {
		b[1]++
	}

	return string(b)
}

// errorResponse constructs an error response with code 86.
func (s *Server) errorResponse(cmd string) []byte {
	return []byte(s.incrementCode(cmd) + "86")
}
