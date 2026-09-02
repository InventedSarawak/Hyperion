// Package config loads nexus's settings through Hyperion's centralized,
// namespaced config system. Every key is nexus.<NAME> -> NEXUS_<NAME>.
package config

import "github.com/inventedsarawak/hyperion/packages/common/config"

// Service is the config namespace for this microservice.
const Service = "nexus"

// Defaults for local development.
const (
	DefaultHTTPAddr   = ":8080"
	DefaultCortexAddr = "localhost:50051"
)

// Config holds nexus's runtime settings.
type Config struct {
	HTTPAddr   string
	CortexAddr string

	loader *config.Loader
}

// Load reads configuration from the environment, applying defaults.
func Load() Config {
	l := config.For(Service)
	return Config{
		loader:     l,
		HTTPAddr:   l.String("HTTP_ADDR", DefaultHTTPAddr),
		CortexAddr: l.String("CORTEX_GRPC_ADDR", DefaultCortexAddr),
	}
}

// Describe returns every resolved setting with secrets masked.
func (c Config) Describe() []config.Entry {
	if c.loader == nil {
		return nil
	}
	return c.loader.Describe()
}
