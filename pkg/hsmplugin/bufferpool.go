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
					b := make([]byte, 0, size)
					return &b
				},
			},
			ringSize: defaultRingSize,
		}
	}

	return &BufferPool{
		buckets:        buckets,
		sizeBuckets:    sizeBuckets,
		resizeHints:    make(map[int]int),
		maxResizeHints: 1000,
	}
}

// getBestBucketSize returns the optimal bucket size for a requested capacity
// using historical resize hints if available.
func (bp *BufferPool) getBestBucketSize(size int) int {
	bp.resizeHintsMu.RLock()
	if hint, ok := bp.resizeHints[size]; ok {
		bp.resizeHintsMu.RUnlock()
		return hint
	}
	bp.resizeHintsMu.RUnlock()

	for _, bs := range bp.sizeBuckets {
		if bs >= size {
			return bs
		}
	}

	return size
}

// Get returns a buffer with at least the given capacity.
func (bp *BufferPool) Get(size int) []byte {
	if size <= 0 {
		return nil
	}

	bp.mu.RLock()
	defer bp.mu.RUnlock()

	bucketSize := bp.getBestBucketSize(size)

	// If larger than our largest bucket, delegate to anet buffer pool
	if bucketSize > bp.sizeBuckets[len(bp.sizeBuckets)-1] {
		return anet.GetBuffer(size)
	}

	bucket := bp.buckets[bucketSize]
	if bucket == nil {
		return anet.GetBuffer(size)
	}

	if buf, ok := bucket.ring.Dequeue(); ok {
		return buf[:size:cap(buf)]
	}

	if rawBuf := bucket.pool.Get(); rawBuf != nil {
		if bufPtr, ok := rawBuf.(*[]byte); ok && bufPtr != nil {
			buf := *bufPtr
			return buf[:size:cap(buf)]
		}
		if buf, ok := rawBuf.([]byte); ok {
			return buf[:size:cap(buf)]
		}
	}

	return anet.GetBuffer(size)
}

// Prewarm initializes the buffer pool with the specified number of buffers per size bucket.
func (bp *BufferPool) Prewarm(count int) {
	if count <= 0 {
		return
	}

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

// Put returns a buffer to the pool for reuse after securely clearing sensitive data.
func (bp *BufferPool) Put(buf []byte) {
	if buf == nil {
		return
	}

	bufCap := cap(buf)
	if bufCap == 0 {
		return
	}

	fullBuf := buf[:bufCap]

	// For oversized buffers, return to anet global pool
	if bufCap > bp.sizeBuckets[len(bp.sizeBuckets)-1] {
		for i := range fullBuf {
			fullBuf[i] = 0
		}
		anet.PutBuffer(fullBuf)
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

	if targetSize > 0 && targetSize <= bp.sizeBuckets[len(bp.sizeBuckets)-1] && bucket != nil {
		// Zero sensitive data
		for i := range fullBuf {
			fullBuf[i] = 0
		}
		buf = fullBuf[:0]

		if ok := bucket.ring.Enqueue(buf); ok {
			bp.mu.RUnlock()
			return
		}

		bCopy := buf
		bucket.pool.Put(&bCopy)
	}
	bp.mu.RUnlock()
}

// Trim releases unused buffers from the pools.
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

	sizes := make([]int, len(bp.sizeBuckets))
	copy(sizes, bp.sizeBuckets)

	return sizes
}
