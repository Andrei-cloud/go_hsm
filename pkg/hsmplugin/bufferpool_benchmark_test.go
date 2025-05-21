package hsmplugin

import (
	"testing"
)

// BenchmarkBufferPool_GetPut benchmarks the basic Get/Put operations.
func BenchmarkBufferPool_GetPut(b *testing.B) {
	pool := NewBufferPool()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf := pool.Get(256)
		pool.Put(buf)
	}
}

// BenchmarkBufferPool_Concurrent benchmarks concurrent Get/Put operations.
func BenchmarkBufferPool_Concurrent(b *testing.B) {
	pool := NewBufferPool()
	const goroutines = 10

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			buf := pool.Get(256)
			pool.Put(buf)
		}
	})
}

// BenchmarkBufferPool_VaryingSizes benchmarks Get/Put with different buffer sizes.
func BenchmarkBufferPool_VaryingSizes(b *testing.B) {
	pool := NewBufferPool()
	sizes := []int{64, 128, 256, 512, 1024, 2048, 4096}
	idx := 0

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		size := sizes[idx]
		buf := pool.Get(size)
		pool.Put(buf)
		idx = (idx + 1) % len(sizes)
	}
}

// BenchmarkBufferPool_PrewarmedVsCold compares performance of prewarmed vs cold pool.
func BenchmarkBufferPool_PrewarmedVsCold(b *testing.B) {
	b.Run("Cold", func(b *testing.B) {
		pool := NewBufferPool()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			buf := pool.Get(256)
			pool.Put(buf)
		}
	})

	b.Run("Prewarmed", func(b *testing.B) {
		pool := NewBufferPool()
		pool.Prewarm(100) // Prewarm with 100 buffers
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			buf := pool.Get(256)
			pool.Put(buf)
		}
	})
}

// BenchmarkBufferPool_ResizeHints benchmarks the effectiveness of resize hints.
func BenchmarkBufferPool_ResizeHints(b *testing.B) {
	pool := NewBufferPool()
	commonSizes := []int{100, 200, 300}
	idx := 0

	// Train the pool first
	for i := 0; i < 1000; i++ {
		for _, size := range commonSizes {
			buf := pool.Get(size)
			pool.Put(buf)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		size := commonSizes[idx]
		buf := pool.Get(size)
		pool.Put(buf)
		idx = (idx + 1) % len(commonSizes)
	}
}

// BenchmarkBufferPool_Oversized benchmarks handling of oversized buffers.
func BenchmarkBufferPool_Oversized(b *testing.B) {
	pool := NewBufferPool()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		buf := pool.Get(8192) // Larger than largest bucket
		pool.Put(buf)
	}
}

// BenchmarkStandardAllocation is a baseline benchmark that uses standard slice allocation.
func BenchmarkStandardAllocation(b *testing.B) {
	for i := 0; i < b.N; i++ {
		buf := make([]byte, 256)
		_ = buf
	}
}
