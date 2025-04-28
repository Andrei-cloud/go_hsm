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

	lmk := os.Getenv("HSM_LMK")
	if lmk == "" {
		log.Warn().Msg("HSM_LMK not set; using default LMK")
		lmk = "0123456789ABCDEFFEDCBA9876543210"
	}

	hsmSvc, err := hsm.NewHSM(lmk)
	if err != nil {
		log.Fatal().Err(err).Msg("failed to initialize HSM service")
	}
	s.hsmSvc = hsmSvc

	if err := s.pluginManager.LoadAll("./commands"); err != nil {
		log.Error().Err(err).Msg("failed to load plugins")
	}

	return s.srv.Start()
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() error {
	return s.srv.Stop()
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
	payload := data[2:]
	reqHex := hex.EncodeToString(data)
	log.Info().
		Str("event", "request_received").
		Str("client_ip", client).
		Str("command", cmd).
		Str("request_hex", reqHex).
		Int("active_connections", int(atomic.LoadInt32(&s.activeConns))).
		Msg("received command")

	// record plugin execution time.
	execStart := time.Now()
	resp, err := s.pluginManager.ExecuteCommand(cmd, payload)
	execDur := time.Since(execStart)
	log.Debug().
		Str("event", "command_executed").
		Str("client_ip", client).
		Str("command", cmd).
		Str("duration", execDur.String()).
		Msg("command execution complete")

	if err != nil {
		if err.Error() == "unknown command" {
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
				Err(err).
				Msg("Plugin execution failed")
			resp = s.errorResponse(cmd)
		}
	}

	rspHex := hex.EncodeToString(resp)
	log.Info().
		Str("event", "response_sent").
		Str("client_ip", client).
		Str("response_hex", rspHex).
		Int("active_connections", int(atomic.LoadInt32(&s.activeConns))).
		Msg("sent response")

	total := time.Since(start)
	log.Debug().
		Str("event", "handle_done").
		Str("request_hex", reqHex).
		Str("response_hex", rspHex).
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
