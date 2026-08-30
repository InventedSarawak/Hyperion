// Package config loads cortex's runtime configuration from the environment.
package config

import (
	"os"
	"strconv"
	"strings"
)

// Defaults for local development via deploy/docker-compose.yml.
const (
	DefaultDatabaseURL      = "postgres://hyperion:hyperion@localhost:5433/hyperion?sslmode=disable"
	DefaultElasticsearchURL = "http://localhost:9200"
	DefaultIndexName        = "hyperion-vulnerabilities"
	DefaultGRPCAddr         = ":50051"
)

// Config holds cortex's runtime settings.
type Config struct {
	DatabaseURL      string
	ElasticsearchURL string
	IndexName        string
	GRPCAddr         string
	ServeGRPC        bool
	ConsumeStdin     bool
}

// Load reads configuration from the environment, applying defaults.
func Load() Config {
	return Config{
		DatabaseURL:      getenv("CORTEX_DATABASE_URL", DefaultDatabaseURL),
		ElasticsearchURL: getenv("CORTEX_ELASTICSEARCH_URL", DefaultElasticsearchURL),
		IndexName:        getenv("CORTEX_INDEX_NAME", DefaultIndexName),
		GRPCAddr:         getenv("CORTEX_GRPC_ADDR", DefaultGRPCAddr),
		ServeGRPC:        getbool("CORTEX_SERVE_GRPC", true),
		ConsumeStdin:     getbool("CORTEX_CONSUME_STDIN", false),
	}
}

func getenv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func getbool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(strings.TrimSpace(v)); err == nil {
			return b
		}
	}
	return fallback
}
