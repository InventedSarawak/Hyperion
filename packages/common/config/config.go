// Package config is Hyperion's centralized configuration system.
//
// Every setting is namespaced by the microservice that owns it. A logical name
// written as SERVICE.VAR maps to the environment variable SERVICE_VAR:
//
//	siphon.NVD_API_KEY   -> SIPHON_NVD_API_KEY
//	cortex.DATABASE_URL  -> CORTEX_DATABASE_URL
//	nexus.HTTP_ADDR      -> NEXUS_HTTP_ADDR
//
// Each service creates one Loader (config.For("siphon")) and reads through it,
// so the prefix is declared once and every lookup is consistent. Values already
// present in the real environment always beat the .env file.
package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Loader reads namespaced configuration for a single microservice.
type Loader struct {
	service string
	seen    []Entry
}

// Entry records a resolved setting, for startup diagnostics.
type Entry struct {
	Key    string // full env var name, e.g. SIPHON_NVD_API_KEY
	Value  string // masked when Secret is true
	Set    bool   // whether the environment supplied it
	Secret bool
}

// For creates a Loader for a service, loading the repo .env file on first use.
// The service name is upper-cased to form the env var prefix.
func For(service string) *Loader {
	LoadDotEnv()
	return &Loader{service: strings.ToUpper(strings.TrimSpace(service))}
}

// Key returns the full environment variable name for a logical name.
func (l *Loader) Key(name string) string {
	return l.service + "_" + strings.ToUpper(strings.TrimSpace(name))
}

// Has reports whether the environment supplies a non-empty value.
func (l *Loader) Has(name string) bool {
	return strings.TrimSpace(os.Getenv(l.Key(name))) != ""
}

// String reads a string setting, falling back to def.
func (l *Loader) String(name, def string) string {
	return l.record(name, def, false)
}

// Secret reads a credential. It is recorded masked for diagnostics and has no
// default: a missing credential is the signal to disable its feature.
func (l *Loader) Secret(name string) string {
	return l.record(name, "", true)
}

// Int reads an integer setting, falling back to def when unset or unparsable.
func (l *Loader) Int(name string, def int) int {
	raw := l.record(name, strconv.Itoa(def), false)
	if n, err := strconv.Atoi(strings.TrimSpace(raw)); err == nil {
		return n
	}
	return def
}

// Bool reads a boolean setting, falling back to def.
func (l *Loader) Bool(name string, def bool) bool {
	raw := l.record(name, strconv.FormatBool(def), false)
	if b, err := strconv.ParseBool(strings.TrimSpace(raw)); err == nil {
		return b
	}
	return def
}

// Duration reads a Go duration (30s, 10m, 1h), falling back to def.
func (l *Loader) Duration(name string, def time.Duration) time.Duration {
	raw := l.record(name, def.String(), false)
	if d, err := time.ParseDuration(strings.TrimSpace(raw)); err == nil {
		return d
	}
	return def
}

// List reads a comma-separated list, falling back to def when empty.
func (l *Loader) List(name string, def []string) []string {
	raw := l.record(name, strings.Join(def, ","), false)
	parts := strings.Split(raw, ",")

	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return def
	}
	return out
}

// Describe returns every setting resolved so far, with secrets masked. Useful
// for logging effective configuration at startup without leaking credentials.
func (l *Loader) Describe() []Entry { return l.seen }

// record resolves one value and remembers it for Describe.
func (l *Loader) record(name, def string, secret bool) string {
	key := l.Key(name)
	raw := strings.TrimSpace(os.Getenv(key))

	set := raw != ""
	value := raw
	if !set {
		value = def
	}

	shown := value
	if secret {
		shown = mask(value)
	}
	l.seen = append(l.seen, Entry{Key: key, Value: shown, Set: set, Secret: secret})

	return value
}

// mask reduces a credential to a non-identifying hint.
func mask(v string) string {
	switch {
	case v == "":
		return "(unset)"
	case len(v) <= 8:
		return "(set)"
	default:
		return v[:4] + "..." + v[len(v)-4:]
	}
}

// LoadDotEnv walks up from the working directory to find a .env file and loads
// it. A missing .env is not an error: everything has a default and credentials
// are optional. Real environment variables are never overwritten.
func LoadDotEnv() {
	dir, err := os.Getwd()
	if err != nil {
		return
	}

	for range 6 {
		candidate := filepath.Join(dir, ".env")
		if _, statErr := os.Stat(candidate); statErr == nil {
			_ = godotenv.Load(candidate)
			return
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return // reached the filesystem root
		}
		dir = parent
	}
}
