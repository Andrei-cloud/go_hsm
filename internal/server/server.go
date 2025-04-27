package server

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	anetserver "github.com/andrei-cloud/anet/server" // use anet TCP server.
	"github.com/andrei-cloud/go_hsm/internal/hsm"
	"github.com/andrei-cloud/go_hsm/internal/plugins"
	"github.com/rs/zerolog/log"
)

// Server wraps the anet TCP server and HSM logic.
type Server struct {
	address       string
	srv           *anetserver.Server
	pluginManager *plugins.PluginManager
	hsmSvc        *hsm.HSM
	activeConns   int32
}

// NewServer configures and returns the HSM server instance.
func NewServer(address string, pm *plugins.PluginManager) (*Server, error) {
	cfg := &anetserver.ServerConfig{
		MaxConns:        100,
		ReadTimeout:     30,
		WriteTimeout:    30,
		IdleTimeout:     60,
		ShutdownTimeout: 5,
	}

	s := &Server{address: address, pluginManager: pm}
	// wrap our handler to the anet/server HandlerFunc.
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

	var resp []byte
	var err error

	if cmd == "A0" {
		encrypted, e := s.hsmSvc.EncryptUnderLMK(payload)
		if e != nil {
			resp = s.errorResponse(cmd)
		} else {
			resp = append([]byte(s.incrementCode(cmd)), encrypted...)
		}
	} else {
		resp, err = s.pluginManager.ExecuteCommand(cmd, payload)
		if err != nil {
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
