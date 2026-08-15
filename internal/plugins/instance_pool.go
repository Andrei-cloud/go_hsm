// Package plugins provides the PluginInstancePool type for managing WASM plugin instance pools.
package plugins

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

var (
	// ErrPoolClosed is returned when an operation is attempted on a closed pool.
	ErrPoolClosed = errors.New("plugin instance pool is closed")
	// ErrPoolTimeout is returned when acquiring an instance times out.
	ErrPoolTimeout = errors.New("timed out waiting for available plugin instance")
)

// PluginInstancePoolInterface defines the interface for managing plugin instance pools.
type PluginInstancePoolInterface interface {
	// Get returns an instance from the pool, creating a new one if needed.
	Get() (*PluginInstance, error)

	// GetWithContext returns an instance from the pool, respecting context cancellation and timeout.
	GetWithContext(ctx context.Context) (*PluginInstance, error)

	// Put returns an instance to the pool or closes it if the pool is full/closed.
	Put(inst *PluginInstance)

	// Close drains and closes all idle instances in the pool.
	Close() error
}

// PluginInstancePool manages a bounded pool of WASM module instances for a plugin.
type PluginInstancePool struct {
	pool       chan *PluginInstance
	maxSize    int
	factory    func() (*PluginInstance, error)
	totalCount int32
	closed     atomic.Bool
	mu         sync.Mutex
}

// NewPluginInstancePool creates a new bounded plugin instance pool.
func NewPluginInstancePool(maxSize int, factory func() (*PluginInstance, error)) *PluginInstancePool {
	if maxSize <= 0 {
		maxSize = 10
	}
	return &PluginInstancePool{
		pool:    make(chan *PluginInstance, maxSize),
		maxSize: maxSize,
		factory: factory,
	}
}

// Get returns an instance from the pool using context.Background.
func (p *PluginInstancePool) Get() (*PluginInstance, error) {
	return p.GetWithContext(context.Background())
}

// GetWithContext returns an instance from the pool, creating one if capacity allows,
// or waiting for an existing instance to be returned until the context is done.
func (p *PluginInstancePool) GetWithContext(ctx context.Context) (*PluginInstance, error) {
	if p.closed.Load() {
		return nil, ErrPoolClosed
	}

	// 1. Fast path: try to acquire an idle instance without blocking.
	select {
	case inst := <-p.pool:
		if inst != nil {
			return inst, nil
		}
	default:
	}

	// 2. Try to create a new instance if we haven't reached maxSize.
	p.mu.Lock()
	if !p.closed.Load() && int(atomic.LoadInt32(&p.totalCount)) < p.maxSize {
		atomic.AddInt32(&p.totalCount, 1)
		p.mu.Unlock()

		inst, err := p.factory()
		if err != nil {
			atomic.AddInt32(&p.totalCount, -1)
			return nil, fmt.Errorf("failed to create plugin instance: %w", err)
		}
		return inst, nil
	}
	p.mu.Unlock()

	// 3. Pool is at capacity: wait for an available instance or context cancellation.
	select {
	case inst := <-p.pool:
		if inst != nil {
			return inst, nil
		}
		return nil, ErrPoolClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Put returns an instance to the pool. If the pool is closed or channel is full,
// the instance is closed immediately to prevent WASM memory leaks.
func (p *PluginInstancePool) Put(inst *PluginInstance) {
	if inst == nil {
		return
	}

	if p.closed.Load() {
		p.closeInstance(inst)
		atomic.AddInt32(&p.totalCount, -1)
		return
	}

	select {
	case p.pool <- inst:
		// Successfully returned to pool
	default:
		// Pool channel full or unexpected excess instance: close it cleanly
		p.closeInstance(inst)
		atomic.AddInt32(&p.totalCount, -1)
	}
}

// Close closes the pool and all idle WASM module instances.
func (p *PluginInstancePool) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	close(p.pool)
	for inst := range p.pool {
		if inst != nil {
			p.closeInstance(inst)
			atomic.AddInt32(&p.totalCount, -1)
		}
	}

	return nil
}

func (p *PluginInstancePool) closeInstance(inst *PluginInstance) {
	if inst != nil && inst.Module != nil {
		_ = inst.Module.Close(context.Background())
	}
}
