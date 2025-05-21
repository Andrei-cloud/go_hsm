// Package plugins provides the PluginInstance type for WASM plugin modules.
package plugins

import "github.com/tetratelabs/wazero/api"

// PluginInstance holds a WASM module instance.
type PluginInstance struct {
	Module        api.Module
	AllocFn       api.Function
	ExecuteFn     api.Function
	VersionFn     api.Function
	DescriptionFn api.Function
	AuthorFn      api.Function
}
