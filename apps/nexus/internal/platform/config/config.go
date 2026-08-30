// Package config loads nexus's runtime configuration from the environment.
package config

import (
	"os"
	"strings"
)

// Defaults for local development.
const (
	DefaultHTTPAddr   = ":8080"
	DefaultCortexAddr = "localhost:50051"
)

// Config holds nexus's runtime settings.
type Config struct {
	HTTPAddr   string
	CortexAddr string
}

// Load reads configuration from the environment, applying defaults.
func Load() Config {
	return Config{
		HTTPAddr:   getenv("NEXUS_HTTP_ADDR", DefaultHTTPAddr),
		CortexAddr: getenv("NEXUS_CORTEX_GRPC_ADDR", DefaultCortexAddr),
	}
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}
