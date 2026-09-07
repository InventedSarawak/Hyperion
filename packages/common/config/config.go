// Package config is Hyperion's centralized configuration system.
//
// Every setting is namespaced by the microservice that owns it. A logical name
// SERVICE.VAR maps to the environment variable SERVICE_VAR:
//
//	siphon.NVD_API_KEY   -> SIPHON_NVD_API_KEY
//	cortex.DATABASE_URL  -> CORTEX_DATABASE_URL
//	nexus.HTTP_ADDR      -> NEXUS_HTTP_ADDR
//
// Underscores are used rather than a literal dot because POSIX shells cannot
// export an identifier containing one ("export SIPHON.NVD_API_KEY=x" is a
// syntax error), which would make one-off overrides impossible.
//
// Each service creates one Loader (config.For("siphon")) so the prefix is
// declared once. A real environment variable always beats the .env file.
package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	Set    bool   // whether a value was supplied (rather than defaulted)
	Secret bool
	From   string // where it came from: "env", ".env", or "" when defaulted
}

// For creates a Loader for a service, loading the repo .env file on first use.
// The service name is upper-cased to form the env var prefix.
func For(service string) *Loader {
	LoadDotEnv()
	return &Loader{service: strings.ToUpper(strings.TrimSpace(service))}
}

// Key returns the full environment variable name for a logical setting.
func (l *Loader) Key(name string) string {
	return l.service + "_" + strings.ToUpper(strings.TrimSpace(name))
}

// Has reports whether a non-empty value is available for this setting.
func (l *Loader) Has(name string) bool {
	_, _, ok := l.lookup(name)
	return ok
}

// lookup resolves a setting, checking the real environment before the .env
// file so a one-off shell override always wins.
func (l *Loader) lookup(name string) (value, source string, ok bool) {
	key := l.Key(name)

	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v, "env", true
	}
	if v := strings.TrimSpace(dotEnv()[key]); v != "" && !isStrayComment(v) {
		return v, ".env", true
	}
	return "", "", false
}

// isStrayComment guards a .env footgun: godotenv strips a trailing "# comment"
// only when the line has a value, so a blank setting written as
//
//	SIPHON_GITHUB_TOKEN=   # format: ghp_...
//
// yields the comment itself as the value. Treating a leading '#' as unset stops
// that from being sent upstream as a credential.
func isStrayComment(v string) bool { return strings.HasPrefix(v, "#") }

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
	raw, from, set := l.lookup(name)

	value := raw
	if !set {
		value = def
	}

	shown := value
	if secret {
		shown = mask(value)
	}
	l.seen = append(l.seen, Entry{
		Key:    l.Key(name),
		Value:  shown,
		Set:    set,
		Secret: secret,
		From:   from,
	})

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

var (
	dotEnvOnce   sync.Once
	dotEnvValues map[string]string
)

// dotEnv returns the parsed .env contents, reading the file at most once.
//
// The file is read into a map rather than injected into the process
// environment. That keeps the precedence rule honest: the loader can tell a
// real environment variable apart from a .env entry, so an explicit shell
// override always wins.
func dotEnv() map[string]string {
	dotEnvOnce.Do(func() {
		dotEnvValues = map[string]string{}

		path, ok := findDotEnv()
		if !ok {
			return
		}
		if values, err := godotenv.Read(path); err == nil {
			dotEnvValues = values
		}
	})
	return dotEnvValues
}

// findDotEnv walks up from the working directory looking for a .env file, so a
// service started from apps/<name> still picks up the repo-root file.
func findDotEnv() (string, bool) {
	dir, err := os.Getwd()
	if err != nil {
		return "", false
	}

	for range 6 {
		candidate := filepath.Join(dir, ".env")
		if _, statErr := os.Stat(candidate); statErr == nil {
			return candidate, true
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false // reached the filesystem root
		}
		dir = parent
	}
	return "", false
}

// LoadDotEnv primes the .env cache. A missing .env is not an error: everything
// has a default and credentials are optional.
func LoadDotEnv() { _ = dotEnv() }
