package plugins

import (
	"sync"
)

// PluginInfo stores metadata about an HSM command plugin.
type PluginInfo struct {
	CommandCode  string
	Version      string
	Description  string
	Author       string
	Capabilities []string
}

// PluginRegistry manages plugin metadata and versioning.
type PluginRegistry struct {
	plugins map[string]*PluginInfo
	mu      sync.RWMutex
}

// NewPluginRegistry creates a new plugin registry.
func NewPluginRegistry() *PluginRegistry {
	return &PluginRegistry{
		plugins: make(map[string]*PluginInfo),
	}
}

// Register adds or updates plugin metadata in the registry.
func (pr *PluginRegistry) Register(info *PluginInfo) {
	pr.mu.Lock()
	defer pr.mu.Unlock()

	pr.plugins[info.CommandCode] = info
}

// Get retrieves plugin metadata by command code.
func (pr *PluginRegistry) Get(commandCode string) (*PluginInfo, bool) {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	info, ok := pr.plugins[commandCode]
	return info, ok
}

// List returns all registered plugins.
func (pr *PluginRegistry) List() []*PluginInfo {
	pr.mu.RLock()
	defer pr.mu.RUnlock()

	result := make([]*PluginInfo, 0, len(pr.plugins))
	for _, info := range pr.plugins {
		result = append(result, info)
	}
	return result
}
