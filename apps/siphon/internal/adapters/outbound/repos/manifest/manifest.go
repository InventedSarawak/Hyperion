// Package manifest parses dependency manifests into domain dependencies. It
// is pure: it takes bytes and returns domain types, with no knowledge of where
// the file came from. That keeps the awkward part of ingestion — real-world
// manifest syntax — testable without a network.
package manifest

import (
	"path"
	"sort"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// Parser reads one manifest format.
type Parser interface {
	// Name identifies the format in logs and errors, e.g. "go.mod".
	Name() string
	// Matches reports whether the file at this repository path is in this
	// format. Manifests live anywhere in a repository — a monorepo has one
	// per service — so formats are recognised by name, not by fixed path.
	Matches(filePath string) bool
	// Parse maps the file's contents onto domain types. filePath is recorded
	// on every dependency, so a finding can be traced to the file that
	// brought it in.
	Parse(filePath string, content []byte) (model.RepositorySnapshot, error)
}

// Parsers returns every manifest format siphon understands.
func Parsers() []Parser {
	return []Parser{
		PackageLock{}, PnpmLock{}, CargoLock{}, PoetryLock{}, ComposerLock{},
		GoMod{}, PackageJSON{},
		Requirements{}, Pyproject{}, Pipfile{},
		Cargo{},
		Pom{}, Gradle{}, VersionCatalog{},
		GemfileLock{}, Gemfile{},
		Composer{},
		MSBuild{}, CentralPackages{}, PackagesConfig{},
		Foundry{},
	}
}

// MaxManifests bounds how many files one scan reads. Each is an API request,
// and a repository with more is nearly always carrying other people's code.
const MaxManifests = 60

// skippedDirs hold files that are not the repository's own dependencies:
// installed packages, build output, and fixtures written to exercise a tool.
// A committed node_modules alone can hold thousands of package.json files,
// none of them a decision the repository made.
var skippedDirs = map[string]bool{
	"node_modules": true, "bower_components": true, "jspm_packages": true, "vendor": true,
	".venv": true, "venv": true, "site-packages": true, "__pycache__": true,
	"target": true, "dist": true, "build": true, "out": true, ".next": true, ".git": true,
	"testdata": true, "fixtures": true, "__fixtures__": true, "examples": true, "example": true,
}

// Found is one file worth reading, and the format to read it as.
type Found struct {
	Path   string
	Parser Parser
}

// Discover picks, out of every file in a repository, the dependency files to
// read — shallowest first, so a monorepo's root and its services come before
// anything buried deep — and reports how many it left out over the cap.
func Discover(paths []string, parsers []Parser) (found []Found, dropped int) {
	present := make(map[string]bool, len(paths))
	for _, p := range paths {
		present[p] = true
	}
	for _, p := range paths {
		if inSkippedDir(p) {
			continue
		}
		// A lockfile's exact versions beat the ranges in the manifest beside it.
		if path.Base(p) == "Gemfile" && present[path.Join(path.Dir(p), "Gemfile.lock")] {
			continue
		}
		for _, parser := range parsers {
			if parser.Matches(p) {
				found = append(found, Found{Path: p, Parser: parser})
				break
			}
		}
	}
	sort.SliceStable(found, func(i, j int) bool {
		di, dj := strings.Count(found[i].Path, "/"), strings.Count(found[j].Path, "/")
		if di != dj {
			return di < dj
		}
		// A lockfile before the manifest beside it: its versions are exact.
		if li, lj := isLockfile(found[i].Parser), isLockfile(found[j].Parser); li != lj {
			return li
		}
		return found[i].Path < found[j].Path
	})
	if len(found) > MaxManifests {
		dropped = len(found) - MaxManifests
		found = found[:MaxManifests]
	}
	return found, dropped
}

// isLockfile reports whether a parser reads resolved versions.
func isLockfile(p Parser) bool {
	_, ok := p.(lockfileParser)
	return ok
}

func inSkippedDir(filePath string) bool {
	segments := strings.Split(filePath, "/")
	for _, s := range segments[:len(segments)-1] {
		if skippedDirs[s] {
			return true
		}
	}
	return false
}

// devFile reports whether a file's name marks it as development-only, as in
// requirements-dev.txt or requirements/test.txt.
func devFile(filePath string) bool {
	b := strings.ToLower(strings.TrimSuffix(path.Base(filePath), path.Ext(filePath)))
	if path.Base(path.Dir(filePath)) == "requirements" {
		b = "requirements-" + b
	}
	for _, marker := range []string{"dev", "test", "lint", "doc"} {
		if strings.Contains(b, marker) {
			return true
		}
	}
	return false
}

func dependency(ecosystem, name, version string, direct bool, file string) model.Dependency {
	return model.Dependency{
		Package:      valueobject.NewPackageRef(ecosystem, name, version),
		Direct:       direct,
		ManifestPath: file,
	}
}

// sortedKeys lists a map's keys in order: Go randomizes map iteration, and two
// reads of an unchanged manifest must produce the same snapshot.
func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}
