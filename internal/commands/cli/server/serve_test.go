package server

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/andrei-cloud/go_hsm/internal/config"
)

// TestRunServeKeepsServingUntilCanceled guards against the regression where
// runServe treated anet's non-blocking Start() as blocking: Start returned
// nil immediately, runServe took that as "server stopped" and exited with
// code 0 before the port could serve any traffic.
func TestRunServeKeepsServingUntilCanceled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve port: %v", err)
	}

	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port

	if err := listener.Close(); err != nil {
		t.Fatalf("failed to release port: %v", err)
	}

	cfg := config.Get()
	cfg.Server.Host = "127.0.0.1"
	cfg.Server.Port = port
	cfg.Plugin.Path = t.TempDir()
	cfg.Plugin.ExecutionTimeout = 2 * time.Second
	cfg.Plugin.PoolSize = 2

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := NewServeCommand()
	cmd.SetContext(ctx)

	serveErr := make(chan error, 1)

	go func() { serveErr <- runServe(cmd, nil) }()

	// The port must accept connections while the server is running.
	dialWhenReady(t, address, serveErr)

	// The command must stay running until the context is canceled.
	select {
	case err := <-serveErr:
		t.Fatalf("runServe exited while server should still be running (err: %v)", err)
	case <-time.After(300 * time.Millisecond):
	}

	cancel()

	waitToReturn(t, serveErr)
}

// TestRunServePortFlagOverridesConfig guards against the config-layering bug
// where --host/--port were bound to the global viper while runServe read
// host/port from config.Get() (populated by a different viper instance), so
// the flags were silently ignored and config.yaml always won.
func TestRunServePortFlagOverridesConfig(t *testing.T) {
	// Reserve two free ports: one for the config value, one for the flag.
	// The server must bind the flag's port, not the config's.
	flagListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve flag port: %v", err)
	}

	flagAddress := flagListener.Addr().String()
	flagPort := flagListener.Addr().(*net.TCPAddr).Port

	if err := flagListener.Close(); err != nil {
		t.Fatalf("failed to release flag port: %v", err)
	}

	cfgListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to reserve config port: %v", err)
	}

	cfgPort := cfgListener.Addr().(*net.TCPAddr).Port

	if err := cfgListener.Close(); err != nil {
		t.Fatalf("failed to release config port: %v", err)
	}

	if flagPort == cfgPort {
		t.Fatalf("reserved identical ports: %d", flagPort)
	}

	cfg := config.Get()
	cfg.Server.Host = "127.0.0.1"
	cfg.Server.Port = cfgPort
	cfg.Plugin.Path = t.TempDir()
	cfg.Plugin.ExecutionTimeout = 2 * time.Second
	cfg.Plugin.PoolSize = 2

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmd := NewServeCommand()

	if err := cmd.Flags().Set("port", strconv.Itoa(flagPort)); err != nil {
		t.Fatalf("failed to set --port flag: %v", err)
	}

	cmd.SetContext(ctx)

	serveErr := make(chan error, 1)

	go func() { serveErr <- runServe(cmd, nil) }()

	// Must become reachable on the flag's port, not the config's.
	dialWhenReady(t, flagAddress, serveErr)

	select {
	case err := <-serveErr:
		t.Fatalf("runServe exited while server should still be running (err: %v)", err)
	case <-time.After(300 * time.Millisecond):
	}

	cancel()

	waitToReturn(t, serveErr)
}

// dialWhenReady dials address until a connection is accepted, failing the
// test if runServe returns, or if nothing accepts within the deadline.
func dialWhenReady(t *testing.T, address string, serveErr chan error) {
	t.Helper()

	deadline := time.Now().Add(5 * time.Second)

	for {
		conn, dialErr := net.Dial("tcp", address)
		if dialErr == nil {
			if closeErr := conn.Close(); closeErr != nil {
				t.Fatalf("failed to close probe connection: %v", closeErr)
			}

			return
		}

		select {
		case err := <-serveErr:
			t.Fatalf("runServe returned before serving on %s (err: %v)", address, err)
		default:
		}

		if time.Now().After(deadline) {
			t.Fatalf("server never accepted a connection on %s: %v", address, dialErr)
		}

		time.Sleep(20 * time.Millisecond)
	}
}

// waitToReturn waits for runServe to return after cancellation without error.
func waitToReturn(t *testing.T, serveErr chan error) {
	t.Helper()

	select {
	case err := <-serveErr:
		if err != nil {
			t.Fatalf("runServe returned error after cancel: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("runServe did not return after context cancellation")
	}
}
