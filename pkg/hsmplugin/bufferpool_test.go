package hsmplugin

import (
	"fmt"
	"sync"
	"testing"
)

func TestBufferPool_GetPut(t *testing.T) {
	// Create a pool with predefined size buckets
	pool := NewBufferPool()

	// Get a buffer of 64 bytes (should match a bucket)
	buf1 := pool.Get(64)
	if len(buf1) != 64 {
		t.Errorf("Expected buffer length 64, got %d", len(buf1))
	}

	// Write some data to the buffer
	for i := range buf1 {
		buf1[i] = byte(i + 1)
	}

	// Return it to the pool
	pool.Put(buf1)

	// Get another buffer - should be the same one, but zeros
	buf2 := pool.Get(64)

	// Verify the buffer was cleared
	for i, b := range buf2 {
		if b != 0 {
			t.Errorf("Buffer not cleared at position %d: expected 0, got %d", i, b)
		}
	}

	// Return the second buffer
	pool.Put(buf2)
}

func TestBufferPool_DifferentSizes(t *testing.T) {
	// Create a pool with predefined size buckets
	pool := NewBufferPool()

	// Get a buffer for specific size
	buf1 := pool.Get(200)
	if len(buf1) != 200 {
		t.Errorf("Expected buffer length 200, got %d", len(buf1))
	}
	// This should use the 256-byte bucket
	if cap(buf1) < 200 {
		t.Errorf("Expected buffer capacity >= 200, got %d", cap(buf1))
	}

	// Get a buffer smaller than the smallest bucket
	buf2 := pool.Get(30)
	if len(buf2) != 30 {
		t.Errorf("Expected buffer length 30, got %d", len(buf2))
	}
	// This should use the 64-byte bucket
	if cap(buf2) < 30 {
		t.Errorf("Expected buffer capacity >= 30, got %d", cap(buf2))
	}

	// Get a buffer of zero size
	buf3 := pool.Get(0)
	if len(buf3) != 0 {
		t.Errorf("Expected buffer length 0, got %d", len(buf3))
	}

	// Get a buffer larger than the largest bucket
	buf4 := pool.Get(8192)
	if len(buf4) != 8192 {
		t.Errorf("Expected buffer length 8192, got %d", len(buf4))
	}
	// This should allocate a new buffer rather than using a bucket
	if cap(buf4) != 8192 {
		t.Errorf("Expected buffer capacity == 8192, got %d", cap(buf4))
	}

	// Return all buffers
	pool.Put(buf1)
	pool.Put(buf2)
	pool.Put(buf3)
	pool.Put(buf4)
}

// Benchmark to show how BufferPool helps reduce garbage collection overhead
// in a more realistic high-throughput HSM scenario with concurrent operations.

// HSMOperation simulates a typical HSM command execution that processes data
type HSMOperation struct {
	inputSize  int
	outputSize int
}

func (op *HSMOperation) ExecuteWithPool(pool *BufferPool) []byte {
	// Get input buffer from pool
	input := pool.Get(op.inputSize)

	// Fill input with test data
	for i := 0; i < op.inputSize; i++ {
		input[i] = byte(i % 256)
	}

	// Process the input (this simulates the actual HSM operation)
	output := pool.Get(op.outputSize)
	for i := 0; i < op.outputSize; i++ {
		if i < op.inputSize {
			output[i] = input[i] ^ 0xFF // Simple transformation
		} else {
			output[i] = byte(i % 256)
		}
	}

	// Return input buffer to the pool
	pool.Put(input)

	// In a real system, we might return output to the pool later
	// but for this benchmark we'll return it as the "response"
	return output
}

func (op *HSMOperation) ExecuteWithoutPool() []byte {
	// Allocate input buffer
	input := make([]byte, op.inputSize)

	// Fill input with test data
	for i := 0; i < op.inputSize; i++ {
		input[i] = byte(i % 256)
	}

	// Process the input (this simulates the actual HSM operation)
	output := make([]byte, op.outputSize)
	for i := 0; i < op.outputSize; i++ {
		if i < op.inputSize {
			output[i] = input[i] ^ 0xFF // Simple transformation
		} else {
			output[i] = byte(i % 256)
		}
	}

	// In a real system without a buffer pool, we'd just let
	// the garbage collector handle the input buffer

	return output
}

func BenchmarkHSMOperations_WithPool(b *testing.B) {
	// Create a pool with predefined buffer sizes
	pool := NewBufferPool()

	// Define a mix of operations with different buffer sizes
	operations := []HSMOperation{
		{inputSize: 128, outputSize: 256},  // Small command
		{inputSize: 512, outputSize: 512},  // Medium command
		{inputSize: 1024, outputSize: 128}, // Large command with small response
	}

	var responses [][]byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Select an operation based on iteration
		op := operations[i%len(operations)]

		// Execute the operation with pool
		response := op.ExecuteWithPool(pool)

		// In a real system, we'd process the response further
		// Here we'll just store it to prevent compiler optimization
		if len(responses) < 5 {
			responses = append(responses, response)
		} else {
			// Return older responses to the pool to simulate
			// response buffers being reused after processing
			pool.Put(responses[0])
			responses = append(responses[1:], response)
		}
	}
}

func BenchmarkHSMOperations_WithoutPool(b *testing.B) {
	// Define the same mix of operations
	operations := []HSMOperation{
		{inputSize: 128, outputSize: 256},  // Small command
		{inputSize: 512, outputSize: 512},  // Medium command
		{inputSize: 1024, outputSize: 128}, // Large command with small response
	}

	var responses [][]byte

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Select an operation based on iteration
		op := operations[i%len(operations)]

		// Execute the operation without pool
		response := op.ExecuteWithoutPool()

		// Same response handling as with pool
		if len(responses) < 5 {
			responses = append(responses, response)
		} else {
			responses = append(responses[1:], response)
		}
	}
}

// ConcurrentBenchmark runs multiple simulated HSM operations concurrently
// to demonstrate the benefits of buffer pooling in high-throughput scenarios
func BenchmarkConcurrentHSMOperations(b *testing.B) {
	// Run with different worker counts to simulate varying levels of concurrency
	for _, workers := range []int{1, 4, 8, 16} {
		b.Run(fmt.Sprintf("WithPool_%dWorkers", workers), func(b *testing.B) {
			// Create a pool with predefined buffer sizes
			pool := NewBufferPool()

			// Define a mix of operations with different buffer sizes
			operations := []HSMOperation{
				{inputSize: 128, outputSize: 256},
				{inputSize: 512, outputSize: 512},
				{inputSize: 1024, outputSize: 128},
			}

			// Create a wait group to synchronize workers
			var wg sync.WaitGroup

			// Channel to distribute work
			workCh := make(chan int, workers*2)

			// Start workers
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()

					// Process work from the channel
					for i := range workCh {
						op := operations[i%len(operations)]
						response := op.ExecuteWithPool(pool)
						pool.Put(response) // Return response buffer to pool
					}
				}()
			}

			// Reset the timer before sending work
			b.ResetTimer()

			// Send b.N operations divided among workers
			for i := 0; i < b.N; i++ {
				workCh <- i
			}

			// Close the channel and wait for workers to finish
			close(workCh)
			wg.Wait()
		})

		b.Run(fmt.Sprintf("WithoutPool_%dWorkers", workers), func(b *testing.B) {
			// Define the same mix of operations
			operations := []HSMOperation{
				{inputSize: 128, outputSize: 256},
				{inputSize: 512, outputSize: 512},
				{inputSize: 1024, outputSize: 128},
			}

			// Create a wait group to synchronize workers
			var wg sync.WaitGroup

			// Channel to distribute work
			workCh := make(chan int, workers*2)

			// Start workers
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()

					// Process work from the channel
					for i := range workCh {
						op := operations[i%len(operations)]
						_ = op.ExecuteWithoutPool() // Response will be GC'd
					}
				}()
			}

			// Reset the timer before sending work
			b.ResetTimer()

			// Send b.N operations divided among workers
			for i := 0; i < b.N; i++ {
				workCh <- i
			}

			// Close the channel and wait for workers to finish
			close(workCh)
			wg.Wait()
		})
	}
}

// Buffer represents a slice of bytes with size and address metadata.

// BenchmarkPoolVsNoPool compares the performance of the bucketed pool against direct allocation.
func BenchmarkPoolVsNoPool(b *testing.B) {
	// Define a mix of realistic buffer sizes
	sizes := []int{
		48,   // Small key data
		96,   // Medium command
		256,  // Typical HSM command
		1000, // Larger than 512 bucket
		1500, // Between 1024-2048 buckets
		5000, // Larger than any bucket
	}

	b.Run("WithPool", func(b *testing.B) {
		pool := NewBufferPool()
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			size := sizes[i%len(sizes)]
			buf := pool.Get(size)
			// Simulate some work
			buf[0] = 1
			if len(buf) > 1 {
				buf[len(buf)-1] = 2
			}
			pool.Put(buf)
		}
	})

	b.Run("NoPool", func(b *testing.B) {
		b.ResetTimer()

		for i := 0; i < b.N; i++ {
			size := sizes[i%len(sizes)]
			buf := make([]byte, size)
			// Simulate same work
			buf[0] = 1
			if len(buf) > 1 {
				buf[len(buf)-1] = 2
			}
			// No put - simulate GC handling it
		}
	})
}

func TestBufferPool_Stats(t *testing.T) {
	pool := NewBufferPool()

	// Reset stats to ensure clean test
	pool.ResetStats()

	// Track some allocations and hits
	buf1 := pool.Get(64)
	buf2 := pool.Get(128)
	buf3 := pool.Get(512)
	buf4 := pool.Get(8192) // Oversized

	// Put some back to create hits on next Get
	pool.Put(buf1)
	pool.Put(buf2)

	// These should be hits
	buf5 := pool.Get(64)
	buf6 := pool.Get(128)
	// Get stats and verify counts
	stats := pool.Stats()

	if stats["allocations"].(int64) != 6 {
		t.Errorf("Expected 6 allocations, got %d", stats["allocations"])
	}

	if stats["hits"].(int64) != 5 {
		t.Errorf("Expected 2 hits, got %d", stats["hits"])
	}

	if stats["misses"].(int64) != 1 {
		t.Errorf("Expected 4 misses, got %d", stats["misses"])
	}

	if stats["oversized"].(int64) != 1 {
		t.Errorf("Expected 1 oversized, got %d", stats["oversized"])
	}

	// Test hit rate calculation
	expectedHitRate := (float64(5) / float64(6)) * 100
	hitRate := stats["hit_rate_pct"].(float64)
	if hitRate < expectedHitRate-0.1 || hitRate > expectedHitRate+0.1 {
		t.Errorf("Expected hit rate approximately %.2f%%, got %.2f%%", expectedHitRate, hitRate)
	}
	// Test reset
	pool.ResetStats()
	stats = pool.Stats()

	if stats["allocations"].(int64) != 0 || stats["hits"].(int64) != 0 ||
		stats["misses"].(int64) != 0 {
		t.Error("Stats were not properly reset to zero")
	}

	// Clean up
	pool.Put(buf3)
	pool.Put(buf4)
	pool.Put(buf5)
	pool.Put(buf6)
}

func TestBufferPool_GetBucketSizes(t *testing.T) {
	pool := NewBufferPool()
	sizes := pool.GetBucketSizes()

	// Should have at least a few predefined bucket sizes
	if len(sizes) < 3 {
		t.Errorf("Expected at least 3 bucket sizes, got %d", len(sizes))
	}

	// Verify increasing order
	for i := 1; i < len(sizes); i++ {
		if sizes[i] <= sizes[i-1] {
			t.Errorf(
				"Bucket sizes should be in increasing order, but %d at index %d is not greater than %d at index %d",
				sizes[i],
				i,
				sizes[i-1],
				i-1,
			)
		}
	}
}
