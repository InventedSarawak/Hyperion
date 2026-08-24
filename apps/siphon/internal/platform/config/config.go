// Package config loads siphon's runtime configuration from the environment.
package config

import (
	"os"
	"time"
)

// Config holds siphon's runtime settings.
type Config struct {
	NVDBaseURL   string        // empty -> nvd.DefaultBaseURL
	NVDAPIKey    string        // optional; raises NVD rate limits
	PollInterval time.Duration // how often to poll the source
	Lookback     time.Duration // how far back the first poll reaches
}

// Load reads configuration from the environment, applying defaults.
func Load() Config {
	return Config{
		NVDBaseURL:   getenv("SIPHON_NVD_BASE_URL", ""),
		NVDAPIKey:    getenv("SIPHON_NVD_API_KEY", ""),
		PollInterval: getduration("SIPHON_POLL_INTERVAL", 10*time.Minute),
		Lookback:     getduration("SIPHON_LOOKBACK", 2*time.Hour),
	}
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getduration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
