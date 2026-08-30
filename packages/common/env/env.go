// Package env loads .env files into the process environment.
//
// Values already present in the real environment always win, so an explicit
// `FOO=bar ./service` invocation overrides the file.
package env

import (
	"os"
	"path/filepath"

	"github.com/joho/godotenv"
)

// Load walks up from the working directory looking for a .env file (so a
// service started from apps/<name> still picks up the repo-root file) and
// loads it if found. A missing .env is not an error: every setting has a
// default, and credentials are optional.
func Load() {
	dir, err := os.Getwd()
	if err != nil {
		return
	}

	for i := 0; i < 6; i++ {
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
