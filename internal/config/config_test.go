package config

import (
	"testing"
)

func TestConfig_Defaults(t *testing.T) {
	if err := Initialize(); err != nil {
		t.Fatalf("failed to initialize config: %v", err)
	}

	cfg := Get()
	if cfg.Server.Host == "" {
		t.Errorf("expected non-empty server host")
	}
	if cfg.Server.Port <= 0 {
		t.Errorf("expected positive port, got %d", cfg.Server.Port)
	}
	if cfg.Server.MaxConns <= 0 {
		t.Errorf("expected positive max conns, got %d", cfg.Server.MaxConns)
	}
	if cfg.Server.MaxConcurrentHandlers <= 0 {
		t.Errorf("expected positive max concurrent handlers, got %d", cfg.Server.MaxConcurrentHandlers)
	}
	if cfg.Server.ReadTimeout <= 0 {
		t.Errorf("expected positive read timeout, got %v", cfg.Server.ReadTimeout)
	}
	if cfg.Server.ShutdownTimeout <= 0 {
		t.Errorf("expected positive shutdown timeout, got %v", cfg.Server.ShutdownTimeout)
	}
	if cfg.Plugin.Path == "" {
		t.Errorf("expected non-empty plugin path")
	}
	if cfg.Plugin.ExecutionTimeout <= 0 {
		t.Errorf("expected positive plugin execution timeout, got %v", cfg.Plugin.ExecutionTimeout)
	}
	if cfg.Plugin.PoolSize <= 0 {
		t.Errorf("expected positive pool size, got %d", cfg.Plugin.PoolSize)
	}
}

func TestConfig_GetViper(t *testing.T) {
	_ = Initialize()
	v := GetViper()
	if v == nil {
		t.Errorf("expected non-nil viper instance")
	}
	if v.GetString("server.host") != "localhost" && v.GetString("server.host") == "" {
		t.Errorf("expected server.host in viper")
	}
}
