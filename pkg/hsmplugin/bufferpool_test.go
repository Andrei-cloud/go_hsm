package hsmplugin

import (
	"fmt"
	"sync"
	"testing"
)

func TestBufferPool_GetPut(t *testing.T) {
	// Create a pool with initial size of 10 bytes
	pool := NewBufferPool(10)

	// Get a buffer of the default size
	buf1 := pool.Get(10)
	if len(buf1) != 10 {
		t.Errorf("Expected buffer length 10, got %d", len(buf1))
	}

	// Write some data to the buffer
	for i := range buf1 {
		buf1[i] = byte(i + 1)
	}

	// Return it to the pool
	pool.Put(buf1)

	// Get another buffer - should be the same one, but zeros
	buf2 := pool.Get(10)

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
	// Create a pool with initial size of 10 bytes
	pool := NewBufferPool(10)

	// Get a buffer larger than the initial size
	buf1 := pool.Get(20)
	if len(buf1) != 20 {
		t.Errorf("Expected buffer length 20, got %d", len(buf1))
	}

	// Get a buffer smaller than the initial size
	buf2 := pool.Get(5)
	if len(buf2) != 5 {
		t.Errorf("Expected buffer length 5, got %d", len(buf2))
	}

	// Get a buffer of zero size (should use minimum size)
	buf3 := pool.Get(0)
	if len(buf3) != 0 {
		t.Errorf("Expected buffer length 0, got %d", len(buf3))
	}

	// Return all buffers
	pool.Put(buf1)
	pool.Put(buf2)
	pool.Put(buf3)
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
	// Create a pool with initial buffer size
	pool := NewBufferPool(512)

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
			// Create a pool with initial buffer size
			pool := NewBufferPool(512)

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
