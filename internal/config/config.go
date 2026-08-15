package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
)

var (
	configData Config
	v          *viper.Viper
)

// Config holds all configuration settings.
type Config struct {
	// Server configuration
	Server struct {
		Host                  string
		Port                  int
		MaxConns              int
		MaxConcurrentHandlers int
		ReadTimeout           time.Duration
		WriteTimeout          time.Duration
		IdleTimeout           time.Duration
		KeepAliveInterval     time.Duration
		ShutdownTimeout       time.Duration
	}
	// Plugin configuration
	Plugin struct {
		Path             string
		ExecutionTimeout time.Duration
		PoolSize         int
	}
	// Logging configuration
	Log struct {
		Level  string
		Format string
	}
}

// Initialize sets up the configuration system.
func Initialize() error {
	v = viper.New()

	// Set config name and paths
	v.SetConfigName("config")        // name of config file (without extension)
	v.SetConfigType("yaml")          // config file type
	v.AddConfigPath(".")             // optionally look for config in working directory
	v.AddConfigPath("$HOME/.go_hsm") // look for config in .go_hsm directory in home
	v.AddConfigPath("/etc/go_hsm/")  // path to look for the config file in

	// Set default values
	setDefaults()

	// Environment variables
	v.SetEnvPrefix("GOHSM") // prefix for env vars
	v.AutomaticEnv()        // read in environment variables that match
	v.SetEnvKeyReplacer(    // replace dots with underscores in env vars
		strings.NewReplacer(".", "_"),
	)

	// Create config file if it doesn't exist
	if err := ensureConfig(); err != nil {
		return fmt.Errorf("error creating config file: %w", err)
	}

	// Read in config file
	if err := v.ReadInConfig(); err != nil {
		// It's okay if we can't find a config file, we'll use defaults
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("error reading config file: %w", err)
		}
	}

	// Unmarshal config into struct
	if err := v.Unmarshal(&configData); err != nil {
		return fmt.Errorf("unable to decode into config struct: %w", err)
	}

	return nil
}

// setDefaults sets default values for all configuration options.
func setDefaults() {
	// Server defaults
	v.SetDefault("server.host", "localhost")
	v.SetDefault("server.port", 1500)
	v.SetDefault("server.maxconns", 1000)
	v.SetDefault("server.maxconcurrenthandlers", 10000)
	v.SetDefault("server.readtimeout", 30*time.Second)
	v.SetDefault("server.writetimeout", 30*time.Second)
	v.SetDefault("server.idletimeout", 0*time.Second)
	v.SetDefault("server.keepaliveinterval", 30*time.Second)
	v.SetDefault("server.shutdowntimeout", 5*time.Second)

	// Plugin defaults
	v.SetDefault("plugin.path", "plugins")
	v.SetDefault("plugin.executiontimeout", 2*time.Second)
	v.SetDefault("plugin.poolsize", 10)

	// Logging defaults
	v.SetDefault("log.level", "info")
	v.SetDefault("log.format", "human")
}

// ensureConfig creates a default config file if none exists.
func ensureConfig() error {
	// Check if config file exists
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".go_hsm")); os.IsNotExist(err) {
		// Create directory
		if err := os.MkdirAll(filepath.Join(os.Getenv("HOME"), ".go_hsm"), 0o755); err != nil {
			return err
		}
	}

	configFile := filepath.Join(os.Getenv("HOME"), ".go_hsm", "config.yaml")
	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		// Create default config file
		defaultConfig := `# GO HSM Configuration File
server:
  host: localhost
  port: 1500
  maxconns: 1000
  maxconcurrenthandlers: 10000
  readtimeout: 30s
  writetimeout: 30s
  idletimeout: 0s
  keepaliveinterval: 30s
  shutdowntimeout: 5s

plugin:
  path: plugins
  executiontimeout: 2s
  poolsize: 10

log:
  level: info
  format: human
`
		if err := os.WriteFile(configFile, []byte(defaultConfig), 0o644); err != nil {
			return err
		}
	}

	return nil
}

// Get returns the current configuration.
func Get() *Config {
	return &configData
}

// GetViper returns the viper instance.
func GetViper() *viper.Viper {
	return v
}
