// Package config loads cortex's runtime configuration from the environment.
package config

import "os"

// DefaultDatabaseURL points at the local docker-compose Postgres.
const DefaultDatabaseURL = "postgres://hyperion:hyperion@localhost:5433/hyperion?sslmode=disable"

// Config holds cortex's runtime settings.
type Config struct {
	DatabaseURL string
}

// Load reads configuration from the environment, applying defaults.
func Load() Config {
	return Config{
		DatabaseURL: getenv("CORTEX_DATABASE_URL", DefaultDatabaseURL),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
