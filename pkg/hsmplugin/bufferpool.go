// Package hsmplugin provides utilities for HSM plugin interactions.
package hsmplugin

import (
	"sync"
)

// BufferPool manages reusable byte slices to reduce allocations and improve performance
// in high-throughput HSM operations. It maintains a pool of pre-allocated buffers that
// can be reused across multiple plugin invocations, significantly reducing GC pressure.
type BufferPool struct {
	pool sync.Pool
}

// NewBufferPool creates a new buffer pool with the specified initial size.
// The initialSize determines the byte length of new buffers created by the pool
// when no existing buffer of sufficient size is available.
//
// Example usage:
//
//	pool := hsmplugin.NewBufferPool(1024) // Create a pool with 1KB initial buffer size
func NewBufferPool(initialSize int) *BufferPool {
	return &BufferPool{
		pool: sync.Pool{
			New: func() any {
				return make([]byte, initialSize)
			},
		},
	}
}

// Get returns a buffer with at least the given capacity.
// If the pool has an available buffer with sufficient capacity, it will be returned.
// Otherwise, a new buffer of the required size will be allocated.
//
// The returned buffer should always be returned to the pool via Put() when no longer needed.
//
// Example usage:
//
//	buf := pool.Get(512) // Get a buffer of at least 512 bytes
//	defer pool.Put(buf)  // Return it to the pool when done
func (bp *BufferPool) Get(minCapacity int) []byte {
	buf := bp.pool.Get().([]byte)
	if cap(buf) < minCapacity {
		// Return to pool and create a larger one
		bp.pool.Put(buf)
		return make([]byte, minCapacity)
	}
	return buf[:minCapacity]
}

// Put returns a buffer to the pool for reuse.
// This method clears all data in the buffer before returning it to the pool,
// ensuring that sensitive cryptographic material isn't leaked.
//
// Always call Put() with buffers obtained from Get() to ensure proper resource management.
func (bp *BufferPool) Put(buf []byte) {
	// Clear sensitive data
	for i := range buf {
		buf[i] = 0
	}
	bp.pool.Put(buf)
}
