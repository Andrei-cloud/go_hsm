package plugins

import (
	"github.com/andrei-cloud/go_hsm/pkg/hsmplugin"
	"github.com/rs/zerolog/log"
)

// GetPluginInstance returns a plugin instance by command name.
func (pm *PluginManager) GetPluginInstance(cmd string) *PluginInstance {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	return pm.plugins[cmd]
}

// GetPluginMetadata returns the metadata from a plugin's exported functions.
func (pm *PluginManager) GetPluginMetadata(cmd string) (version, description, author string) {
	inst := pm.GetPluginInstance(cmd)
	if inst == nil {
		log.Debug().Str("command", cmd).Msg("plugin instance not found")
		return "N/A", "Error: Plugin not loaded", "N/A"
	}

	log.Debug().Str("command", cmd).
		Bool("has_version", inst.VersionFn != nil).
		Bool("has_desc", inst.DescriptionFn != nil).
		Bool("has_author", inst.AuthorFn != nil).
		Msg("checking plugin functions")

	// Call plugin functions to get metadata

	if inst.VersionFn != nil {
		if results, err := inst.VersionFn.Call(pm.ctx); err == nil && len(results) > 0 {
			ptr, size := hsmplugin.UnpackResult(uint64(results[0]))
			if size > 0 {
				if bytes, ok := inst.Module.Memory().Read(uint32(ptr), uint32(size)); ok {
					version = string(bytes)
				}
			}
		}
	}

	if inst.DescriptionFn != nil {
		if results, err := inst.DescriptionFn.Call(pm.ctx); err == nil && len(results) > 0 {
			ptr, size := hsmplugin.UnpackResult(uint64(results[0]))
			if size > 0 {
				if bytes, ok := inst.Module.Memory().Read(uint32(ptr), uint32(size)); ok {
					description = string(bytes)
				}
			}
		}
	}

	if inst.AuthorFn != nil {
		if results, err := inst.AuthorFn.Call(pm.ctx); err == nil && len(results) > 0 {
			ptr, size := hsmplugin.UnpackResult(uint64(results[0]))
			if size > 0 {
				if bytes, ok := inst.Module.Memory().Read(uint32(ptr), uint32(size)); ok {
					author = string(bytes)
				}
			}
		}
	}

	if version == "" {
		version = "N/A"
	}
	if description == "" {
		description = "N/A"
	}
	if author == "" {
		author = "N/A"
	}

	return version, description, author
}
