package manifest

import (
	"path"
	"regexp"
	"slices"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
)

// --- Gemfile.lock ---

// GemfileLock parses Bundler's lockfile: the exact version of every gem the
// app runs, not just the ones it asked for.
type GemfileLock struct{}

// Name identifies the format.
func (GemfileLock) Name() string { return "Gemfile.lock" }

func (GemfileLock) lockfile() {}

// Matches reports whether the file is a Gemfile.lock.
func (GemfileLock) Matches(filePath string) bool { return path.Base(filePath) == "Gemfile.lock" }

var (
	// lockSpec is a top-level spec — exactly four spaces in — not one of its
	// own requirements, which sit at six.
	lockSpec       = regexp.MustCompile(`^    ([^\s(]+) \(([^)]+)\)$`)
	lockDependency = regexp.MustCompile(`^  ([^\s(!]+)`)
	platformSuffix = regexp.MustCompile(`^(x86|x64|arm|aarch|java|universal|mingw|mswin|darwin|linux)`)
)

// Parse records every locked gem at its exact version; the ones the Gemfile
// named (DEPENDENCIES) are direct, the rest came along with them.
func (GemfileLock) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var (
		section string
		inSpecs bool
		specs   [][2]string
		direct  = map[string]bool{}
	)
	for _, line := range strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n") {
		if line == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			section, inSpecs = strings.TrimSpace(line), false
			continue
		}
		switch section {
		case "GEM", "GIT":
			if strings.TrimSpace(line) == "specs:" {
				inSpecs = true
				continue
			}
			if m := lockSpec.FindStringSubmatch(line); inSpecs && m != nil {
				specs = append(specs, [2]string{m[1], lockedVersion(m[2])})
			}
		case "DEPENDENCIES":
			if m := lockDependency.FindStringSubmatch(line); m != nil {
				direct[m[1]] = true
			}
		}
	}
	var snapshot model.RepositorySnapshot
	for _, s := range specs {
		snapshot.Dependencies = append(snapshot.Dependencies, locked("rubygems", s[0], s[1], direct[s[0]], filePath))
	}
	return snapshot, nil
}

// lockedVersion drops a platform suffix: "1.13.10-x86_64-linux" is 1.13.10.
func lockedVersion(v string) string {
	if i := strings.IndexByte(v, '-'); i > 0 && platformSuffix.MatchString(v[i+1:]) {
		return v[:i]
	}
	return v
}

// --- Gemfile ---

// Gemfile parses a Gemfile, for repositories that do not commit the lock.
type Gemfile struct{}

// Name identifies the format.
func (Gemfile) Name() string { return "Gemfile" }

// Matches reports whether the file is a Gemfile.
func (Gemfile) Matches(filePath string) bool { return path.Base(filePath) == "Gemfile" }

var (
	gemDeclaration = regexp.MustCompile(`^\s*gem\s+["']([^"']+)["']((?:\s*,\s*["'][^"']*["'])*)`)
	quotedString   = regexp.MustCompile(`["']([^"']*)["']`)
	blockOpen      = regexp.MustCompile(`\bdo\s*(\|[^|]*\|)?\s*$`)
)

// Parse reads each gem and its constraints ("~> 7.0", ">= 7.0.1"). Gems in a
// development or test group are recorded as indirect.
func (Gemfile) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var (
		snapshot model.RepositorySnapshot
		blocks   []bool // open do…end blocks: true for a development or test group
	)
	for _, line := range strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, "#"):
			continue
		case blockOpen.MatchString(trimmed):
			blocks = append(blocks, strings.HasPrefix(trimmed, "group") &&
				(strings.Contains(trimmed, ":development") || strings.Contains(trimmed, ":test")))
			continue
		case trimmed == "end":
			if len(blocks) > 0 {
				blocks = blocks[:len(blocks)-1]
			}
			continue
		}
		m := gemDeclaration.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		var constraints []string
		for _, q := range quotedString.FindAllStringSubmatch(m[2], -1) {
			constraints = append(constraints, q[1])
		}
		dev := slices.Contains(blocks, true)
		file := filePath
		if dev {
			file += " (dev)"
		}
		snapshot.Dependencies = append(snapshot.Dependencies,
			dependency("rubygems", m[1], strings.Join(constraints, ", "), !dev, file))
	}
	return snapshot, nil
}
