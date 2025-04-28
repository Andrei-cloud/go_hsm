//nolint:all
package server_test

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/andrei-cloud/anet"
	"github.com/andrei-cloud/go_hsm/internal/plugins"
	server "github.com/andrei-cloud/go_hsm/internal/server"
)

const testAddr = "127.0.0.1:1500"

// startTestServer starts the HSM server for testing.
func startTestServer(t *testing.T) *server.Server {
	t.Helper()
	pm := plugins.NewPluginManager(context.Background())
	err := pm.LoadAll("../../commands")
	if err != nil {
		t.Fatalf("failed to load plugins: %v", err)
	}

	srv, err := server.NewServer(testAddr, pm)
	if err != nil {
		t.Fatalf("failed to initialize server: %v", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := srv.Start(); err != nil {
			errChan <- err
		}
		close(errChan)
	}()

	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("server start error: %v", err)
		}
	case <-time.After(1 * time.Second):
		// Allow some time for the server to start
	}

	time.Sleep(100 * time.Millisecond)

	return srv
}

// TestEncryptUnderLMK verifies the built-in A0 command encrypts payload under LMK.
func TestEncryptUnderLMK(t *testing.T) {
	srv := startTestServer(t)
	defer srv.Stop()

	factory := func(addr string) (anet.PoolItem, error) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err != nil {
			return nil, err
		}

		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			conn.Close()

			return nil, err
		}

		return conn, nil
	}

	pool := anet.NewPool(1, factory, testAddr, nil)
	defer pool.Close()

	broker := anet.NewBroker([]anet.Pool{pool}, 1, nil, nil)
	go broker.Start()
	defer broker.Close()

	payload := make([]byte, 16)
	req := append([]byte("A0"), payload...)
	resp, err := broker.Send(&req)
	if err != nil {
		t.Fatalf("encryption failed: %v", err)
	}

	if len(resp) != 18 {
		t.Fatalf("unexpected response length: got %d, want %d", len(resp), 18)
	}

	if string(resp[:2]) != "A1" {
		t.Fatalf("unexpected response code: got %s, want %s", resp[:2], "A1")
	}
}

// TestUnknownCommand verifies the server responds with incremented code and 86 for unknown commands.
func TestUnknownCommand(t *testing.T) {
	srv := startTestServer(t)
	defer srv.Stop()

	factory := func(addr string) (anet.PoolItem, error) {
		conn, err := net.DialTimeout("tcp", addr, 500*time.Millisecond)
		if err != nil {
			return nil, err
		}

		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			conn.Close()

			return nil, err
		}

		return conn, nil
	}

	pool := anet.NewPool(1, factory, testAddr, nil)
	defer pool.Close()

	broker := anet.NewBroker([]anet.Pool{pool}, 1, nil, nil)
	go broker.Start()
	defer broker.Close()

	req := []byte("ZZ0123")
	resp, err := broker.Send(&req)
	if err != nil {
		t.Fatalf("unknown command request failed: %v", err)
	}

	if len(resp) != 4 {
		t.Fatalf("unexpected error response length: got %d, want 4", len(resp))
	}

	if string(resp) != "ZA86" {
		t.Fatalf("unexpected error response: got %s, want %s", resp, "ZA86")
	}
}
