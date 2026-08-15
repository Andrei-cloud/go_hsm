// Package plugins provides the PluginInstance type for WASM plugin modules.
package plugins

import "github.com/tetratelabs/wazero/api"

// PluginInstanceInterface defines the interface for plugin instances.
type PluginInstanceInterface interface {
	// GetModule returns the underlying WASM module.
	GetModule() api.Module

	// GetAllocFunction returns the memory allocation function.
	GetAllocFunction() api.Function

	// GetExecuteFunction returns the command execution function.
	GetExecuteFunction() api.Function

	// GetVersionFunction returns the version metadata function.
	GetVersionFunction() api.Function

	// GetDescriptionFunction returns the description metadata function.
	GetDescriptionFunction() api.Function

	// GetAuthorFunction returns the author metadata function.
	GetAuthorFunction() api.Function
}

// PluginInstance holds a WASM module instance.
type PluginInstance struct {
	Module        api.Module
	AllocFn       api.Function
	ExecuteFn     api.Function
	VersionFn     api.Function
	DescriptionFn api.Function
	AuthorFn      api.Function
}

// GetModule returns the underlying WASM module.
func (p *PluginInstance) GetModule() api.Module {
	return p.Module
}

// GetAllocFunction returns the memory allocation function.
func (p *PluginInstance) GetAllocFunction() api.Function {
	return p.AllocFn
}

// GetExecuteFunction returns the command execution function.
func (p *PluginInstance) GetExecuteFunction() api.Function {
	return p.ExecuteFn
}

// GetVersionFunction returns the version metadata function.
func (p *PluginInstance) GetVersionFunction() api.Function {
	return p.VersionFn
}

// GetDescriptionFunction returns the description metadata function.
func (p *PluginInstance) GetDescriptionFunction() api.Function {
	return p.DescriptionFn
}

// GetAuthorFunction returns the author metadata function.
func (p *PluginInstance) GetAuthorFunction() api.Function {
	return p.AuthorFn
}
