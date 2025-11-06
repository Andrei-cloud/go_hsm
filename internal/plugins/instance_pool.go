// Package plugins provides the PluginInstancePool type for managing WASM plugin instance pools.
package plugins

// PluginInstancePoolInterface defines the interface for managing plugin instance pools.
type PluginInstancePoolInterface interface {
	// Get returns an instance from the pool, creating a new one if needed.
	Get() (*PluginInstance, error)

	// Put returns an instance to the pool.
	Put(inst *PluginInstance)
}

// PluginInstancePool manages a pool of WASM module instances for a plugin.
type PluginInstancePool struct {
	pool    chan *PluginInstance
	maxSize int
	factory func() (*PluginInstance, error)
}

// Get returns an instance from the pool, creating a new one if needed.
func (p *PluginInstancePool) Get() (*PluginInstance, error) {
	select {
	case inst := <-p.pool:
		return inst, nil
	default:
		if len(p.pool) < p.maxSize {
			return p.factory()
		}
		// Wait for an instance to become available.
		return <-p.pool, nil
	}
}

// Put returns an instance to the pool.
func (p *PluginInstancePool) Put(inst *PluginInstance) {
	select {
	case p.pool <- inst:
		// returned to pool
	default:
		// pool full, drop instance
	}
}
