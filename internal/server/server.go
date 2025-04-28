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
	log.Logger.Info().Msg(fmt.Sprint(v...))
}

func (l logAdapter) Printf(format string, v ...any) {
	log.Logger.Info().Msgf(format, v...)
}

func (l logAdapter) Infof(format string, v ...any) {
	log.Logger.Info().Msgf(format, v...)
}

func (l logAdapter) Warnf(format string, v ...any) {
	log.Logger.Warn().Msgf(format, v...)
}

func (l logAdapter) Errorf(format string, v ...any) {
	log.Logger.Error().Msgf(format, v...)
}

// NewServer configures and returns the HSM server instance.
func NewServer(address string, pm *plugins.PluginManager) (*Server, error) {
	cfg := &anetserver.ServerConfig{
		MaxConns:        100,
		ReadTimeout:     30,
		WriteTimeout:    30,
		IdleTimeout:     60,
		ShutdownTimeout: 5,
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
	log.Info().
		Str("address", s.address).
		Msg("server started")

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

// handle processes incoming HSM requests using WASM plugins or built-in handlers.
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
		Str("description", s.pluginManager.GetDescription(cmd)).
		Str("request_hex", reqHex).
		Int("active_connections", int(atomic.LoadInt32(&s.activeConns))).
		Msg("received command")

	log.Debug().Int("payload_len", len(payload)).Msg("payload length")

	var resp []byte
	var err error

	if cmd == "A0" {
		encStart := time.Now()
		log.Debug().Str("event", "encrypt_under_lmk_start").Msg("starting LMK encryption")

		encrypted, e := s.hsmSvc.EncryptUnderLMK(payload)
		if e != nil {
			resp = s.errorResponse(cmd)
		} else {
			log.Debug().Int64("duration_ms", time.Since(encStart).Milliseconds()).Msg("LMK encryption complete")

			resp = append([]byte(s.incrementCode(cmd)), encrypted...)
		}
	} else {
		execStart := time.Now()
		log.Debug().Str("event", "plugin_execute_start").Str("command", cmd).Msg("invoking plugin")

		resp, err = s.pluginManager.ExecuteCommand(cmd, payload)
		if err != nil {
			resp = s.errorResponse(cmd)
		} else {
			log.Debug().Int64("duration_ms", time.Since(execStart).Milliseconds()).Msg("plugin execution complete")
		}
	}

	rspHex := hex.EncodeToString(resp)
	log.Info().
		Str("event", "response_sent").
		Str("client_ip", client).
		Str("response_hex", rspHex).
		Int("active_connections", int(atomic.LoadInt32(&s.activeConns))).
		Msg("sent response")

	log.Debug().
		Str("event", "handle_done").
		Int64("total_ms", time.Since(start).Milliseconds()).
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
