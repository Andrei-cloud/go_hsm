package hsmplugin

import (
	"sync"
	"testing"
)

// TestBufferPool_StatsSimple tests the basic statistics collection of the BufferPool.
func TestBufferPool_StatsSimple(t *testing.T) {
	pool := NewBufferPool()
	pool.ResetStats()

	// Operations to track
	buf1 := pool.Get(100) // Should be a miss, use 128 bucket
	pool.Put(buf1)        // Put it back
	buf2 := pool.Get(100) // Should be a hit from 128 bucket

	// Verify stats
	stats := pool.Stats()

	// We expect 2 allocations
	if stats["allocations"].(int64) != 2 {
		t.Errorf("expected 2 allocations, got %d", stats["allocations"].(int64))
	}

	// We expect at least 1 hit
	if stats["hits"].(int64) < 1 {
		t.Errorf("expected at least 1 hit, got %d", stats["hits"].(int64))
	}

	// Make sure hit_rate_pct is calculated
	hitRate := stats["hit_rate_pct"].(float64)
	if hitRate < 0 || hitRate > 100 {
		t.Errorf("hit rate should be between 0-100%%, got %.2f%%", hitRate)
	}

	// Clean up
	pool.Put(buf2)

	// Test reset capability
	pool.ResetStats()
	stats = pool.Stats()

	// All counters should be zero after reset
	if stats["allocations"].(int64) != 0 {
		t.Errorf("reset failed: allocations = %d", stats["allocations"].(int64))
	}
	if stats["hits"].(int64) != 0 {
		t.Errorf("reset failed: hits = %d", stats["hits"].(int64))
	}
	if stats["misses"].(int64) != 0 {
		t.Errorf("reset failed: misses = %d", stats["misses"].(int64))
	}
}

// TestBufferPool_OversizedAllocation tests the tracking of buffers larger than any bucket.
func TestBufferPool_OversizedAllocation(t *testing.T) {
	pool := NewBufferPool()
	pool.ResetStats()

	// Get a buffer larger than the largest bucket
	buf := pool.Get(10000) // Should be oversized
	if len(buf) != 10000 {
		t.Errorf("expected buffer length 10000, got %d", len(buf))
	}

	stats := pool.Stats()
	if stats["oversized"].(int64) != 1 {
		t.Errorf("expected 1 oversized allocation, got %d", stats["oversized"].(int64))
	}

	// Clean up
	pool.Put(buf)
}

// TestBufferPool_Prewarm tests the prewarming functionality.
func TestBufferPool_Prewarm(t *testing.T) {
	pool := NewBufferPool()
	pool.ResetStats()

	// Prewarm the pool
	pool.Prewarm(5)

	// Getting buffers after prewarming should result in hits
	for i := 0; i < 5; i++ {
		buf := pool.Get(64) // Smallest bucket size
		if len(buf) != 64 {
			t.Errorf("expected buffer length 64, got %d", len(buf))
		}
		pool.Put(buf)
	}

	stats := pool.Stats()
	if stats["hits"].(int64) < 4 { // Allow for some variance
		t.Errorf("expected at least 4 hits after prewarming, got %d", stats["hits"].(int64))
	}
}

// TestBufferPool_ResizeHints tests the resize hint tracking functionality.
func TestBufferPool_ResizeHints(t *testing.T) {
	pool := NewBufferPool()
	pool.ResetStats()

	// Use some common sizes repeatedly
	commonSizes := []int{100, 200, 300}
	iterations := 100

	// Train the pool with common sizes
	for i := 0; i < iterations; i++ {
		for _, size := range commonSizes {
			buf := pool.Get(size)
			pool.Put(buf)
		}
	}

	// Verify that hits are increasing due to resize hints
	stats := pool.Stats()
	hitRate := stats["hit_rate_pct"].(float64)
	if hitRate < 50.0 { // Expect at least 50% hit rate after training
		t.Errorf("expected hit rate > 50%%, got %.2f%%", hitRate)
	}
}

// TestBufferPool_Concurrency tests the thread safety of the buffer pool.
func TestBufferPool_Concurrency(t *testing.T) {
	pool := NewBufferPool()
	pool.ResetStats()

	const goroutines = 10
	const iterations = 1000
	const bufferSize = 256

	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				buf := pool.Get(bufferSize)
				pool.Put(buf)
			}
		}()
	}

	wg.Wait()

	stats := pool.Stats()
	totalOps := goroutines * iterations
	if stats["allocations"].(int64) != int64(totalOps) {
		t.Errorf("expected %d total operations, got %d", totalOps, stats["allocations"].(int64))
	}
}
