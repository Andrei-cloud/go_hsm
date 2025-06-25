// Package hsmplugin provides utilities for HSM plugin interactions.
package hsmplugin

import (
	"sync"

	"github.com/andrei-cloud/anet"
)

const defaultRingSize = 32

type bufferBucket struct {
	ring     *anet.RingBuffer[[]byte]
	pool     *sync.Pool
	ringSize int
}

// BufferPool manages reusable byte slices to reduce allocations and improve performance
// in high-throughput HSM operations. It maintains multiple pools of pre-allocated buffers
// organized by size buckets that can be reused across multiple plugin invocations,
// significantly reducing GC pressure and memory fragmentation.
type BufferPool struct {
	buckets     map[int]*bufferBucket
	sizeBuckets []int
	mu          sync.RWMutex

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
	buckets := make(map[int]*bufferBucket, len(sizeBuckets))

	for _, size := range sizeBuckets {
		size := size // Capture for closure
		buckets[size] = &bufferBucket{
			ring: anet.NewRingBuffer[[]byte](defaultRingSize),
			pool: &sync.Pool{
				New: func() any {
					return make([]byte, 0, size)
				},
			},
			ringSize: defaultRingSize,
		}
	}

	return &BufferPool{
		buckets:        buckets,
		sizeBuckets:    sizeBuckets,
		resizeHints:    make(map[int]int),
		maxResizeHints: 1000, // Track up to 1000 size hints
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

	// Get optimal bucket size using hints
	bucketSize := bp.getBestBucketSize(size)

	// Check if we need an oversized buffer
	if bucketSize > bp.sizeBuckets[len(bp.sizeBuckets)-1] {
		return make([]byte, size)
	}

	bucket := bp.buckets[bucketSize]
	if bucket == nil {
		return make([]byte, size)
	}

	if buf, ok := bucket.ring.Dequeue(); ok {
		return buf[:size:cap(buf)]
	}

	rawBuf := bucket.pool.Get()
	if bufPtr, ok := rawBuf.(*[]byte); ok && bufPtr != nil {
		buf := *bufPtr
		return buf[:size:cap(buf)]
	}

	// Fallback: try direct slice (backward compatibility)
	if buf, ok := rawBuf.([]byte); ok {
		return buf[:size:cap(buf)]
	}

	// Something went wrong with the type assertion
	return make([]byte, size)
}

// Prewarm initializes the buffer pool with the specified number of buffers per size bucket.
// This can help reduce allocation pressure during high-load periods.
//
// Example usage:
//
//	p.Prewarm(10) // Pre-allocate 10 buffers of each size.
func (bp *BufferPool) Prewarm(count int) {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	for _, size := range bp.sizeBuckets {
		pool := bp.buckets[size]
		if pool == nil {
			continue
		}

		for range count {
			b := make([]byte, 0, size)
			pool.pool.Put(&b)
		}
	}
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

	bp.mu.RLock()
	var targetSize int
	var bucket *bufferBucket
	for _, size := range bp.sizeBuckets {
		if size >= bufCap {
			targetSize = size
			bucket = bp.buckets[size]
			break
		}
	}

	// If the buffer fits in a bucket, clear and return it
	if targetSize > 0 && targetSize <= bp.sizeBuckets[len(bp.sizeBuckets)-1] && bucket != nil {
		// Clear sensitive data
		for i := range buf {
			buf[i] = 0
		}
		// Reset length but preserve capacity
		buf = buf[:0:cap(buf)]

		if ok := bucket.ring.Enqueue(buf); ok {
			bp.mu.RUnlock()

			return
		}

		bucket.pool.Put(&buf)
	}
	bp.mu.RUnlock()
}

// Trim releases unused buffers from the pools to the garbage collector.
// This is useful in low-memory situations or during idle periods.
func (bp *BufferPool) Trim() {
	bp.mu.RLock()
	defer bp.mu.RUnlock()

	for _, bucket := range bp.buckets {
		for {
			_, ok := bucket.ring.Dequeue()
			if !ok {
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
