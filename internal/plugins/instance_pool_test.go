package plugins

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPluginInstancePool_GetPut(t *testing.T) {
	var createCount int32

	factory := func() (*PluginInstance, error) {
		atomic.AddInt32(&createCount, 1)
		return &PluginInstance{}, nil
	}

	pool := NewPluginInstancePool(5, factory)
	defer pool.Close()

	// Get first instance (should trigger factory)
	inst1, err := pool.Get()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if atomic.LoadInt32(&createCount) != 1 {
		t.Fatalf("expected 1 instance created, got %d", createCount)
	}

	// Put it back
	pool.Put(inst1)

	// Get again (should reuse inst1, not trigger factory)
	inst2, err := pool.Get()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inst2 != inst1 {
		t.Errorf("expected reused instance")
	}
	if atomic.LoadInt32(&createCount) != 1 {
		t.Fatalf("expected 1 instance created after reuse, got %d", createCount)
	}

	pool.Put(inst2)
}

func TestPluginInstancePool_ConcurrencyAndBoundedCapacity(t *testing.T) {
	maxSize := 4
	var createCount int32

	factory := func() (*PluginInstance, error) {
		atomic.AddInt32(&createCount, 1)
		return &PluginInstance{}, nil
	}

	pool := NewPluginInstancePool(maxSize, factory)
	defer pool.Close()

	var wg sync.WaitGroup
	numWorkers := 20
	iterations := 50

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				inst, err := pool.GetWithContext(ctx)
				cancel()
				if err != nil {
					t.Errorf("failed to get instance: %v", err)
					return
				}
				time.Sleep(time.Millisecond)
				pool.Put(inst)
			}
		}()
	}

	wg.Wait()

	totalCreated := atomic.LoadInt32(&createCount)
	if int(totalCreated) > maxSize {
		t.Errorf("expected total created instances <= %d, got %d", maxSize, totalCreated)
	}
}

func TestPluginInstancePool_ContextTimeout(t *testing.T) {
	maxSize := 1
	factory := func() (*PluginInstance, error) {
		return &PluginInstance{}, nil
	}

	pool := NewPluginInstancePool(maxSize, factory)
	defer pool.Close()

	// Acquire only available instance
	inst, err := pool.Get()
	if err != nil {
		t.Fatalf("failed to get instance: %v", err)
	}

	// Next GetWithContext with short timeout should timeout
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err = pool.GetWithContext(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected context.DeadlineExceeded, got %v", err)
	}

	// Return instance
	pool.Put(inst)

	// Now acquisition should succeed
	ctx2, cancel2 := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel2()
	inst2, err := pool.GetWithContext(ctx2)
	if err != nil {
		t.Fatalf("expected successful acquisition after Put, got %v", err)
	}
	pool.Put(inst2)
}

func TestPluginInstancePool_Close(t *testing.T) {
	factory := func() (*PluginInstance, error) {
		return &PluginInstance{}, nil
	}

	pool := NewPluginInstancePool(5, factory)
	inst, err := pool.Get()
	if err != nil {
		t.Fatalf("failed to get instance: %v", err)
	}
	pool.Put(inst)

	if err := pool.Close(); err != nil {
		t.Fatalf("error closing pool: %v", err)
	}

	// Subsequent Get should return ErrPoolClosed
	_, err = pool.Get()
	if !errors.Is(err, ErrPoolClosed) {
		t.Fatalf("expected ErrPoolClosed, got %v", err)
	}
}
