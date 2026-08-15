package server

import (
	"context"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/andrei-cloud/anet"
	"github.com/andrei-cloud/go_hsm/internal/config"
	"github.com/andrei-cloud/go_hsm/internal/hsm"
	"github.com/andrei-cloud/go_hsm/internal/plugins"
	"github.com/rs/zerolog"
)

func TestThroughputAndLatencyLoadTest(t *testing.T) {
	// Disable logging during throughput test
	zerolog.SetGlobalLevel(zerolog.Disabled)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	hsmInstance, err := hsm.NewHSM(hsm.FirmwareVersion, false)
	if err != nil {
		t.Fatalf("failed to create HSM: %v", err)
	}

	pm := plugins.NewPluginManager(ctx, hsmInstance, plugins.WithPoolSize(128))
	if err := pm.LoadAll("../../plugins"); err != nil {
		t.Logf("load plugins warning: %v", err)
	}
	defer pm.Close()

	cfg := config.Get()
	addr := "127.0.0.1:19550"

	srv, err := NewServer(addr, pm, WithConfig(cfg), WithServerContext(ctx))
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	go func() {
		_ = srv.Start()
	}()
	defer func() {
		_ = srv.Stop()
	}()

	// Wait for server to listen
	for i := 0; i < 50; i++ {
		c, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
		if err == nil {
			c.Close()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	concurrencies := []int{1, 10, 50, 100}
	totalRequestsPerWorker := 1000

	t.Logf("\n=== HSM THROUGHPUT & LATENCY BENCHMARK ===")
	t.Logf("%-12s | %-12s | %-12s | %-10s | %-10s | %-10s", "Concurrency", "Throughput", "Total Reqs", "P50 Latency", "P90 Latency", "P99 Latency")
	t.Logf("--------------------------------------------------------------------------------")

	for _, concurrency := range concurrencies {
		factory := func(targetAddr string) (anet.PoolItem, error) {
			return net.DialTimeout("tcp", targetAddr, 2*time.Second)
		}
		pool := anet.NewPool(uint32(concurrency), factory, addr, nil)
		broker := anet.NewBroker([]anet.Pool{pool}, concurrency, nil, nil)
		go func() { _ = broker.Start() }()

		var wg sync.WaitGroup
		totalRequests := concurrency * totalRequestsPerWorker

		// Collect latencies
		allLatencies := make([][]time.Duration, concurrency)
		for c := 0; c < concurrency; c++ {
			allLatencies[c] = make([]time.Duration, 0, totalRequestsPerWorker)
		}

		req := []byte("NC") // Test with NC (firmware inquiry)

		start := time.Now()

		for w := 0; w < concurrency; w++ {
			workerID := w
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := 0; i < totalRequestsPerWorker; i++ {
					reqCopy := make([]byte, len(req))
					copy(reqCopy, req)

					t0 := time.Now()
					resp, err := broker.Send(&reqCopy)
					lat := time.Since(t0)

					if err != nil {
						t.Errorf("worker %d failed send: %v", workerID, err)
						return
					}
					if len(resp) == 0 {
						t.Errorf("worker %d got empty response", workerID)
						return
					}
					allLatencies[workerID] = append(allLatencies[workerID], lat)
				}
			}()
		}

		wg.Wait()
		elapsed := time.Since(start)

		broker.Close()
		pool.Close()

		// Aggregate latencies
		flatLatencies := make([]time.Duration, 0, totalRequests)
		for _, lats := range allLatencies {
			flatLatencies = append(flatLatencies, lats...)
		}
		sort.Slice(flatLatencies, func(i, j int) bool {
			return flatLatencies[i] < flatLatencies[j]
		})

		qps := float64(totalRequests) / elapsed.Seconds()
		p50 := flatLatencies[int(float64(len(flatLatencies))*0.50)]
		p90 := flatLatencies[int(float64(len(flatLatencies))*0.90)]
		p99 := flatLatencies[int(float64(len(flatLatencies))*0.99)]

		t.Logf("%-12d | %-10.0f req/s | %-12d | %-10v | %-10v | %-10v",
			concurrency, qps, totalRequests, p50, p90, p99)
	}
	t.Logf("================================================================================\n")
}
