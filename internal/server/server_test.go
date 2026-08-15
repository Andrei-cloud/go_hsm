package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/andrei-cloud/anet"
	anetserver "github.com/andrei-cloud/anet/server"
	"github.com/andrei-cloud/go_hsm/internal/config"
	"github.com/andrei-cloud/go_hsm/internal/hsm"
	"github.com/andrei-cloud/go_hsm/internal/plugins"
)

func TestServer_IncrementCode(t *testing.T) {
	s := &Server{}

	tests := []struct {
		input    string
		expected string
	}{
		{"A0", "A1"},
		{"NC", "ND"},
		{"AZ", "AA"},
		{"B9", "B:"},
		{"A", "A"},
		{"", ""},
	}

	for _, tt := range tests {
		result := s.incrementCode(tt.input)
		if result != tt.expected {
			t.Errorf("incrementCode(%q) = %q; expected %q", tt.input, result, tt.expected)
		}
	}
}

func TestServer_HandleMalformedAndUnknown(t *testing.T) {
	ctx := context.Background()
	hsmInstance, err := hsm.NewHSM(hsm.FirmwareVersion, false)
	if err != nil {
		t.Fatalf("failed to create HSM: %v", err)
	}

	pm := plugins.NewPluginManager(ctx, hsmInstance)
	defer pm.Close()

	srv, err := NewServer("127.0.0.1:18501", pm)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Test malformed request (len < 2)
	conn := &anetserver.ServerConn{
		Conn: &fakeNetConn{},
	}
	_, err = srv.handle(conn, []byte("A"))
	if err == nil {
		t.Errorf("expected error for data len < 2, got nil")
	}

	// Test unknown command
	resp, err := srv.handle(conn, []byte("ZZtestdata"))
	if err != nil {
		t.Fatalf("unexpected error on unknown command: %v", err)
	}
	if string(resp) != "ZA68" {
		t.Errorf("expected ZA68, got %q", string(resp))
	}
}

func TestServer_ActiveConnsTracking(t *testing.T) {
	s := &Server{}
	if s.ActiveConns() != 0 {
		t.Errorf("expected 0 active conns, got %d", s.ActiveConns())
	}
}

func TestServer_FullTCPCycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hsmInstance, err := hsm.NewHSM(hsm.FirmwareVersion, false)
	if err != nil {
		t.Fatalf("failed to create HSM: %v", err)
	}

	pm := plugins.NewPluginManager(ctx, hsmInstance)
	defer pm.Close()

	cfg := config.Get()
	addr := "127.0.0.1:18502"

	srv, err := NewServer(addr, pm, WithConfig(cfg), WithServerContext(ctx))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	go func() {
		_ = srv.Start()
	}()

	// Poll until server is listening
	var conn net.Conn
	for i := 0; i < 50; i++ {
		time.Sleep(20 * time.Millisecond)
		conn, err = net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			break
		}
	}
	if err != nil {
		t.Fatalf("failed to connect to server at %s: %v", addr, err)
	}
	defer conn.Close()

	// Send unknown command with 4-byte header "0000" + command "ZZ" + payload "123456"
	req := []byte("0000ZZ123456")
	if err := anet.Write(conn, req); err != nil {
		t.Fatalf("failed to send request: %v", err)
	}

	resp, err := anet.Read(conn)
	if err != nil {
		t.Fatalf("failed to read response: %v", err)
	}

	expected := "0000ZA68"
	if string(resp) != expected {
		t.Errorf("expected response %q, got %q", expected, string(resp))
	}

	_ = srv.Stop()
}

type fakeNetConn struct {
	net.Conn
}

func (f *fakeNetConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 12345,
	}
}
