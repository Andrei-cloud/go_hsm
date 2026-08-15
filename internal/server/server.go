// Package server wraps the TCP server and HSM logic for processing HSM commands.
package server

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	anetserver "github.com/andrei-cloud/anet/server"
	"github.com/andrei-cloud/go_hsm/internal/config"
	"github.com/andrei-cloud/go_hsm/internal/errorcodes"
	"github.com/andrei-cloud/go_hsm/internal/hsm"
	"github.com/andrei-cloud/go_hsm/internal/plugins"
	"github.com/andrei-cloud/go_hsm/pkg/common"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
)

const requestIDKey contextKey = "request_id"

// contextKey is a custom type for context keys to avoid collisions.
type contextKey string

// logAdapter implements anet.Logger using zerolog.
type logAdapter struct{}

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

// ServerOption defines functional options for Server.
type ServerOption func(*Server)

// WithServerContext sets the parent context for the server lifecycle.
func WithServerContext(ctx context.Context) ServerOption {
	return func(s *Server) {
		if ctx != nil {
			s.ctx = ctx
		}
	}
}

// WithConfig sets server network configuration from config.Config.
func WithConfig(cfg *config.Config) ServerOption {
	return func(s *Server) {
		if cfg != nil {
			s.cfg = cfg
		}
	}
}

// Server handles HSM requests over TCP by delegating to WASM plugins.
type Server struct {
	ctx                 context.Context
	address             string
	cfg                 *config.Config
	srv                 *anetserver.Server
	pluginManager       *plugins.PluginManager
	pluginManagerHolder atomic.Value // stores *plugins.PluginManager
	hsmSvc              hsm.HSMInterface
	activeConns         int32
}

// NewServer configures and returns a new Server listening on the given address using the provided PluginManager.
func NewServer(address string, pm *plugins.PluginManager, opts ...ServerOption) (*Server, error) {
	s := &Server{
		ctx:           context.Background(),
		address:       address,
		pluginManager: pm,
		hsmSvc:        pm.HSM(),
	}

	for _, opt := range opts {
		opt(s)
	}

	s.pluginManagerHolder.Store(pm)

	// Build anet ServerConfig
	serverCfg := &anetserver.ServerConfig{
		MaxConns:              1000,
		MaxConcurrentHandlers: 10000,
		ReadTimeout:           30 * time.Second,
		WriteTimeout:          30 * time.Second,
		IdleTimeout:           0 * time.Second,
		KeepAliveInterval:     30 * time.Second,
		ShutdownTimeout:       5 * time.Second,
		Logger:                logAdapter{},
	}

	if s.cfg != nil {
		if s.cfg.Server.MaxConns > 0 {
			serverCfg.MaxConns = s.cfg.Server.MaxConns
		}
		if s.cfg.Server.MaxConcurrentHandlers > 0 {
			serverCfg.MaxConcurrentHandlers = s.cfg.Server.MaxConcurrentHandlers
		}
		if s.cfg.Server.ReadTimeout > 0 {
			serverCfg.ReadTimeout = s.cfg.Server.ReadTimeout
		}
		if s.cfg.Server.WriteTimeout > 0 {
			serverCfg.WriteTimeout = s.cfg.Server.WriteTimeout
		}
		if s.cfg.Server.IdleTimeout > 0 {
			serverCfg.IdleTimeout = s.cfg.Server.IdleTimeout
		}
		if s.cfg.Server.KeepAliveInterval > 0 {
			serverCfg.KeepAliveInterval = s.cfg.Server.KeepAliveInterval
		}
		if s.cfg.Server.ShutdownTimeout > 0 {
			serverCfg.ShutdownTimeout = s.cfg.Server.ShutdownTimeout
		}
	}

	handler := anetserver.HandlerFunc(s.handle)
	srv, err := anetserver.NewServer(address, handler, serverCfg)
	if err != nil {
		return nil, fmt.Errorf("server setup failed: %w", err)
	}
	s.srv = srv

	return s, nil
}

// Start begins listening for connections and processing requests.
func (s *Server) Start() error {
	log.Info().Str("address", s.address).Msg("server started")

	return s.srv.Start()
}

// Stop gracefully shuts down the server.
func (s *Server) Stop() error {
	return s.srv.Stop()
}

// ActiveConns returns the current number of active connections being processed.
func (s *Server) ActiveConns() int32 {
	return atomic.LoadInt32(&s.activeConns)
}

// SetPluginManager atomically replaces the PluginManager and closes the old one.
func (s *Server) SetPluginManager(newPM *plugins.PluginManager) {
	old, ok := s.pluginManagerHolder.Load().(*plugins.PluginManager)
	if !ok {
		log.Error().Msg("failed to load old plugin manager")
		return
	}

	s.pluginManagerHolder.Store(newPM)

	if err := old.Close(); err != nil {
		log.Error().Err(err).Msg("failed to close old plugin manager")
	}
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

// errorResponse constructs an error response with code 68.
func (s *Server) errorResponse(cmd string) []byte {
	return []byte(s.incrementCode(cmd) + errorcodes.Err68.CodeOnly())
}

// Enhanced error handling and logging for unknown commands and errors.
func (s *Server) handle(conn *anetserver.ServerConn, data []byte) ([]byte, error) {
	client := conn.Conn.RemoteAddr().String()
	atomic.AddInt32(&s.activeConns, 1)
	defer atomic.AddInt32(&s.activeConns, -1)

	requestID := uuid.NewString()

	start := time.Now()
	log.Debug().
		Str("event", "handle_start").
		Str("client_ip", client).
		Str("request_id", requestID).
		Msg("starting request handling")

	if len(data) < 2 {
		log.Error().Str("client_ip", client).Str("request_id", requestID).Msg("malformed request")

		return nil, errors.New("malformed request")
	}

	cmd := string(data[:2])
	origPayload := data[2:]

	var resp []byte
	var execErr error

	pm, ok := s.pluginManagerHolder.Load().(*plugins.PluginManager)
	if !ok {
		log.Error().
			Str("event", "plugin_manager_load_error").
			Str("request_id", requestID).
			Msg("failed to load plugin manager")

		return nil, errors.New("plugin manager load failed")
	}

	execPayload := origPayload
	if cmd == "NC" {
		execPayload = []byte(s.hsmSvc.FirmwareVersion())
	}

	// Pass requestID via context for plugin and plugin logs
	ctx := context.WithValue(srvContextOrDefault(s), requestIDKey, requestID)
	resp, execErr = pm.ExecuteCommandWithContext(ctx, cmd, execPayload)

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

	// unified processed log with duration and error status
	duration := time.Since(start)
	reqStr := common.FormatData(data)
	respStr := common.FormatData(resp)
	if execErr != nil {
		log.Error().
			Str("event", "request_processed").
			Str("client_ip", client).
			Str("command", cmd).
			Str("request_id", requestID).
			Str("request", reqStr).
			Str("response", respStr).
			Str("duration", duration.String()).
			Err(execErr).
			Msg("command execution failed")
	} else {
		log.Info().
			Str("event", "request_processed").
			Str("client_ip", client).
			Str("command", cmd).
			Str("request_id", requestID).
			Str("request", reqStr).
			Str("response", respStr).
			Str("duration", duration.String()).
			Msg("command processed")
	}

	return resp, nil
}

func srvContextOrDefault(s *Server) context.Context {
	if s != nil && s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}
