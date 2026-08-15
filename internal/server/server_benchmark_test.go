package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/andrei-cloud/anet"
	anetserver "github.com/andrei-cloud/anet/server"
	"github.com/andrei-cloud/go_hsm/internal/config"
	"github.com/andrei-cloud/go_hsm/internal/hsm"
	"github.com/andrei-cloud/go_hsm/internal/plugins"
	"github.com/rs/zerolog"
)

func init() {
	// Disable logging during benchmarks to measure pure throughput
	zerolog.SetGlobalLevel(zerolog.Disabled)
}

// BenchmarkServer_HandleInProcess benchmarks the server handle method in-process
// isolating parsing, plugin dispatch, and response formatting from network latency.
func BenchmarkServer_HandleInProcess(b *testing.B) {
	ctx := context.Background()
	hsmInstance, err := hsm.NewHSM(hsm.FirmwareVersion, false)
	if err != nil {
		b.Fatalf("failed to create HSM: %v", err)
	}

	pm := plugins.NewPluginManager(ctx, hsmInstance, plugins.WithPoolSize(32))
	if err := pm.LoadAll("../../plugins"); err != nil {
		b.Logf("load plugins warning (some plugins may be missing): %v", err)
	}
	defer pm.Close()

	srv, err := NewServer("127.0.0.1:0", pm)
	if err != nil {
		b.Fatalf("failed to create server: %v", err)
	}

	conn := &anetserver.ServerConn{
		Conn: &fakeNetConn{},
	}
	reqData := []byte("NC") // Firmware inquiry command

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := srv.handle(conn, reqData)
			if err != nil {
				b.Errorf("handle error: %v", err)
				return
			}
			if len(resp) == 0 {
				b.Errorf("empty response")
				return
			}
		}
	})
}

// BenchmarkServer_EndToEndTCP benchmarks the full TCP request/response pipeline
// with concurrent clients over anet connection pooling.
func BenchmarkServer_EndToEndTCP(b *testing.B) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hsmInstance, err := hsm.NewHSM(hsm.FirmwareVersion, false)
	if err != nil {
		b.Fatalf("failed to create HSM: %v", err)
	}

	pm := plugins.NewPluginManager(ctx, hsmInstance, plugins.WithPoolSize(64))
	if err := pm.LoadAll("../../plugins"); err != nil {
		b.Logf("load plugins warning: %v", err)
	}
	defer pm.Close()

	cfg := config.Get()
	addr := "127.0.0.1:19500"

	srv, err := NewServer(addr, pm, WithConfig(cfg), WithServerContext(ctx))
	if err != nil {
		b.Fatalf("failed to create server: %v", err)
	}

	go func() {
		_ = srv.Start()
	}()
	defer func() {
		_ = srv.Stop()
	}()

	// Wait for listener to be active
	for i := 0; i < 50; i++ {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	for _, workers := range []int{1, 4, 16, 64} {
		b.Run(fmt.Sprintf("Workers_%d", workers), func(b *testing.B) {
			factory := func(targetAddr string) (anet.PoolItem, error) {
				return net.DialTimeout("tcp", targetAddr, 2*time.Second)
			}
			pool := anet.NewPool(uint32(workers), factory, addr, nil)
			defer pool.Close()

			broker := anet.NewBroker([]anet.Pool{pool}, workers, nil, nil)
			go func() { _ = broker.Start() }()
			defer broker.Close()

			req := []byte("NC") // Will be framed as [TaskID (4 bytes)][NC] by broker

			var wg sync.WaitGroup
			workPerWorker := b.N / workers
			if workPerWorker == 0 {
				workPerWorker = 1
			}

			b.ResetTimer()
			b.ReportAllocs()

			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < workPerWorker; i++ {
						rCopy := make([]byte, len(req))
						copy(rCopy, req)
						resp, err := broker.Send(&rCopy)
						if err != nil {
							b.Errorf("send error: %v", err)
							return
						}
						if len(resp) == 0 {
							b.Errorf("empty response")
							return
						}
					}
				}()
			}

			wg.Wait()
		})
	}
}
