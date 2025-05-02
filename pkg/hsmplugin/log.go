// Package hsmplugin provides helper functions for WASM plugins.
package hsmplugin

// LogToHost logs a message from a WASM plugin to the host.
//
//go:wasm-module env
//export log_debug
func LogToHost(string) {}
