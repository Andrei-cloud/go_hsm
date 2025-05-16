// Package hsmplugin provides utilities for HSM plugin interactions.
package hsmplugin

import (
	"sync"
)

// BufferPool manages reusable byte slices to reduce allocations and improve performance
// in high-throughput HSM operations. It maintains multiple pools of pre-allocated buffers
// organized by size buckets that can be reused across multiple plugin invocations,
// significantly reducing GC pressure and memory fragmentation.
type BufferPool struct {
	pools       map[int]*sync.Pool
	sizeBuckets []int
	mu          sync.RWMutex

	// Metrics for pool usage
	hits        int64        // Counter for buffer reuse hits
	misses      int64        // Counter for buffer allocation misses
	allocations int64        // Counter for total allocations
	oversized   int64        // Counter for buffers that exceeded the largest bucket
	resized     int64        // Counter for buffer resizes
	statsMu     sync.RWMutex // Separate mutex for statistics to avoid contention

	// Resize hints track common buffer sizes to optimize bucket allocation
	resizeHints    map[int]int // Maps requested sizes to actual sizes
	resizeHintsMu  sync.RWMutex
	maxResizeHints int // Maximum number of resize hints to track
}

// NewBufferPool creates a new buffer pool with predefined size buckets
// optimized for common HSM operation sizes.
//
// Example usage:
//
//	pool := hsmplugin.NewBufferPool() // Create a pool with predefined size buckets
func NewBufferPool() *BufferPool {
	// Define common buffer sizes for HSM operations.
	sizeBuckets := []int{64, 128, 256, 512, 1024, 2048, 4096}
	pools := make(map[int]*sync.Pool, len(sizeBuckets))

	for _, size := range sizeBuckets {
		size := size // Capture for closure
		pools[size] = &sync.Pool{
			New: func() any {
				return make([]byte, 0, size)
			},
		}
	}

	return &BufferPool{
		pools:          pools,
		sizeBuckets:    sizeBuckets,
		resizeHints:    make(map[int]int),
		maxResizeHints: 1000, // Track up to 1000 size hints
	}
}

// trackResizeHint records a mapping between requested and actual buffer sizes
// to optimize future allocations. It uses a soft limit to prevent unbounded growth.
func (bp *BufferPool) trackResizeHint(requested, actual int) {
	bp.resizeHintsMu.Lock()
	defer bp.resizeHintsMu.Unlock()

	// Only track if we haven't hit the limit
	if len(bp.resizeHints) < bp.maxResizeHints {
		bp.resizeHints[requested] = actual
	}
}

// getBestBucketSize returns the optimal bucket size for a requested capacity
// using historical resize hints if available.
func (bp *BufferPool) getBestBucketSize(size int) int {
	// Check resize hints first
	bp.resizeHintsMu.RLock()
	if hint, ok := bp.resizeHints[size]; ok {
		bp.resizeHintsMu.RUnlock()
		return hint
	}
	bp.resizeHintsMu.RUnlock()

	// Find the smallest bucket that can accommodate the size
	for _, bs := range bp.sizeBuckets {
		if bs >= size {
			return bs
		}
	}

	return size // If no bucket is large enough, return requested size
}

// Get returns a buffer with at least the given capacity.
// It uses resize hints to optimize bucket selection and tracks buffer usage patterns.
//
// The returned buffer should always be returned to the pool via Put() when no longer needed.
//
// Example usage:
//
//	buf := pool.Get(512) // Get a buffer of at least 512 bytes
//	defer pool.Put(buf)  // Return it to the pool when done
func (bp *BufferPool) Get(size int) []byte {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	// Track total allocations
	bp.statsMu.Lock()
	bp.allocations++
	bp.statsMu.Unlock()

	// Get optimal bucket size using hints
	bucketSize := bp.getBestBucketSize(size)

	// Check if we need an oversized buffer
	if bucketSize > bp.sizeBuckets[len(bp.sizeBuckets)-1] {
		bp.statsMu.Lock()
		bp.oversized++
		bp.misses++
		bp.statsMu.Unlock()
		return make([]byte, size)
	}

	// Get from pool
	pool := bp.pools[bucketSize]
	if pool == nil {
		// Shouldn't happen if getBestBucketSize works correctly
		bp.statsMu.Lock()
		bp.misses++
		bp.statsMu.Unlock()
		return make([]byte, size)
	}

	rawBuf := pool.Get()
	if buf, ok := rawBuf.([]byte); ok {
		if cap(buf) == 0 {
			bp.statsMu.Lock()
			bp.misses++
			bp.statsMu.Unlock()
		} else {
			bp.statsMu.Lock()
			bp.hits++
			bp.statsMu.Unlock()
		}
		// Return slice with correct length but full capacity
		return buf[:size:cap(buf)]
	}

	// Something went wrong with the type assertion
	bp.statsMu.Lock()
	bp.misses++
	bp.statsMu.Unlock()
	return make([]byte, size)
}

// Put returns a buffer to the pool for reuse.
// The buffer will be automatically trimmed if it's significantly larger than needed.
//
// Example usage:
//
//	buf := pool.Get(512)
//	defer pool.Put(buf)
func (bp *BufferPool) Put(buf []byte) {
	if buf == nil {
		return
	}

	bufCap := cap(buf)
	// Don't pool oversized buffers
	if bufCap > bp.sizeBuckets[len(bp.sizeBuckets)-1] {
		return
	}

	// Find the appropriate bucket
	bp.mu.RLock()
	var targetSize int
	for _, size := range bp.sizeBuckets {
		if size >= bufCap {
			targetSize = size
			break
		}
	}

	// If the buffer fits in a bucket, clear and return it
	if targetSize > 0 && targetSize <= bp.sizeBuckets[len(bp.sizeBuckets)-1] {
		// Clear sensitive data
		for i := range buf {
			buf[i] = 0
		}
		// Reset length but preserve capacity
		buf = buf[:0:cap(buf)]
		pool := bp.pools[targetSize]
		if pool != nil {
			pool.Put(buf)
		}
	}
	bp.mu.RUnlock()
}

// Prewarm initializes the buffer pool with the specified number of buffers per size bucket.
// This can help reduce allocation pressure during high-load periods.
//
// Example usage:
//
//	pool.Prewarm(10) // Pre-allocate 10 buffers of each size
func (bp *BufferPool) Prewarm(count int) {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	for _, size := range bp.sizeBuckets {
		pool := bp.pools[size]
		if pool == nil {
			continue
		}

		buffers := make([][]byte, count)
		for i := 0; i < count; i++ {
			buffers[i] = make([]byte, 0, size)
			pool.Put(buffers[i])
		}
	}
}

// Stats returns a map of statistics about the buffer pool's performance.
// The statistics include:
// - allocations: Total number of buffer requests
// - hits: Number of times an existing buffer was reused
// - misses: Number of times a new buffer had to be allocated
// - oversized: Number of buffers that exceeded the largest bucket size
// - hit_rate_pct: Percentage of requests that were served from the pool
// - bucket_stats: Map of per-bucket statistics
func (bp *BufferPool) Stats() map[string]any {
	bp.statsMu.RLock()
	defer bp.statsMu.RUnlock()

	stats := make(map[string]any)
	stats["allocations"] = bp.allocations
	stats["hits"] = bp.hits
	stats["misses"] = bp.misses
	stats["oversized"] = bp.oversized
	stats["resized"] = bp.resized

	// Calculate hit rate as percentage
	if bp.allocations > 0 {
		hitRate := float64(bp.hits) / float64(bp.allocations) * 100.0
		stats["hit_rate_pct"] = hitRate
	} else {
		stats["hit_rate_pct"] = 0.0
	}

	return stats
}

// ResetStats resets all performance counters to zero.
// This is useful for gathering statistics over specific time periods.
func (bp *BufferPool) ResetStats() {
	bp.statsMu.Lock()
	defer bp.statsMu.Unlock()

	bp.allocations = 0
	bp.hits = 0
	bp.misses = 0
	bp.oversized = 0
	bp.resized = 0
}

// Trim releases unused buffers from the pools to the garbage collector.
// This is useful in low-memory situations or during idle periods.
func (bp *BufferPool) Trim() {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	for _, pool := range bp.pools {
		// Get and immediately discard all buffers
		for {
			buf := pool.Get()
			if buf == nil {
				break
			}
		}
	}
}

// GetBucketSizes returns the available buffer bucket sizes.
func (bp *BufferPool) GetBucketSizes() []int {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	// Create a copy to avoid sharing the internal slice
	sizes := make([]int, len(bp.sizeBuckets))
	copy(sizes, bp.sizeBuckets)
	return sizes
}
