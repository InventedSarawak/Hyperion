package manifest

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
)

// A lockfile records the versions actually installed; a manifest records only
// the range allowed. The difference decides whether a finding can be judged
// outright: "^1.13.2" may or may not install the compromised axios 1.14.1,
// while a lockfile saying 1.13.2 settles it.
//
// Lockfiles are read alongside their manifest, not instead of it. The manifest
// says which dependencies are direct and what the repository publishes; the
// lockfile says which versions are there, transitive ones included.

// lockfileParser marks a parser whose versions are exact, so discovery reads
// it before the manifest beside it.
type lockfileParser interface{ lockfile() }

// locked builds a dependency whose version came from a lockfile.
func locked(ecosystem, name, version string, direct bool, file string) model.Dependency {
	d := dependency(ecosystem, name, version, direct, file)
	d.Locked = true
	return d
}

// --- npm: package-lock.json ---

// PackageLock parses npm's package-lock.json (lockfileVersion 2 and 3).
type PackageLock struct{}

// Name identifies the format.
func (PackageLock) Name() string { return "package-lock.json" }

// Matches reports whether the file is a package-lock.json.
func (PackageLock) Matches(filePath string) bool { return path.Base(filePath) == "package-lock.json" }

func (PackageLock) lockfile() {}

type packageLockEntry struct {
	Version string            `json:"version"`
	Dev     bool              `json:"dev"`
	Link    bool              `json:"link"`
	Deps    map[string]string `json:"dependencies"`
}

// Parse maps every installed package. The root entry names the direct ones.
func (PackageLock) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var f struct {
		Packages map[string]packageLockEntry `json:"packages"`
	}
	if err := json.Unmarshal(content, &f); err != nil {
		return model.RepositorySnapshot{}, fmt.Errorf("manifest: parse %s: %w", filePath, err)
	}
	direct := map[string]bool{}
	for name := range f.Packages[""].Deps {
		direct[name] = true
	}

	var snapshot model.RepositorySnapshot
	for _, key := range sortedKeys(f.Packages) {
		entry := f.Packages[key]
		name, ok := packageLockName(key)
		if !ok || entry.Version == "" || entry.Link {
			continue // the root project, a workspace link, or no version
		}
		snapshot.Dependencies = append(snapshot.Dependencies,
			locked("npm", name, entry.Version, direct[name] && !entry.Dev, filePath))
	}
	return snapshot, nil
}

// packageLockName reads the package name out of a key such as
// "node_modules/@scope/pkg", or a nested "node_modules/a/node_modules/b".
func packageLockName(key string) (string, bool) {
	i := strings.LastIndex(key, "node_modules/")
	if i < 0 {
		return "", false
	}
	name := key[i+len("node_modules/"):]
	return name, name != ""
}

// --- npm: pnpm-lock.yaml ---

// PnpmLock parses pnpm's lockfile, whose importers are the workspace's
// packages and whose top-level list is everything resolved.
type PnpmLock struct{}

// Name identifies the format.
func (PnpmLock) Name() string { return "pnpm-lock.yaml" }

// Matches reports whether the file is a pnpm-lock.yaml.
func (PnpmLock) Matches(filePath string) bool { return path.Base(filePath) == "pnpm-lock.yaml" }

func (PnpmLock) lockfile() {}

type pnpmEntry struct {
	Specifier string `yaml:"specifier"`
	Version   string `yaml:"version"`
}

// Parse maps each importer's dependencies and every resolved package.
func (PnpmLock) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var f struct {
		Importers map[string]struct {
			Dependencies         map[string]pnpmEntry `yaml:"dependencies"`
			DevDependencies      map[string]pnpmEntry `yaml:"devDependencies"`
			OptionalDependencies map[string]pnpmEntry `yaml:"optionalDependencies"`
		} `yaml:"importers"`
		Packages map[string]struct{} `yaml:"packages"`
	}
	if err := yaml.Unmarshal(content, &f); err != nil {
		return model.RepositorySnapshot{}, fmt.Errorf("manifest: parse %s: %w", filePath, err)
	}

	var snapshot model.RepositorySnapshot
	add := func(entries map[string]pnpmEntry, direct bool, file string) {
		for _, name := range sortedKeys(entries) {
			if v := pnpmVersion(entries[name].Version); v != "" {
				snapshot.Dependencies = append(snapshot.Dependencies, locked("npm", name, v, direct, file))
			}
		}
	}
	for _, importer := range sortedKeys(f.Importers) {
		where := filePath
		if importer != "." && importer != "" {
			where = filePath + " (" + importer + ")"
		}
		add(f.Importers[importer].Dependencies, true, where)
		add(f.Importers[importer].DevDependencies, false, where+" (dev)")
		add(f.Importers[importer].OptionalDependencies, false, where)
	}
	// Everything the workspace resolved, transitive packages included.
	for _, key := range sortedKeys(f.Packages) {
		if name, version, ok := pnpmPackageKey(key); ok {
			snapshot.Dependencies = append(snapshot.Dependencies, locked("npm", name, version, false, filePath))
		}
	}
	return snapshot, nil
}

// pnpmVersion drops the peer suffix pnpm appends — "9.39.2(jiti@2.6.1)" — and
// rejects links and tarball references, which name no registry version.
func pnpmVersion(v string) string {
	if i := strings.IndexByte(v, '('); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(v)
	if v == "" || strings.ContainsAny(v, "/:") {
		return ""
	}
	return v
}

// pnpmPackageKey splits "@scope/pkg@1.2.3" into its name and version.
func pnpmPackageKey(key string) (name, version string, ok bool) {
	at := strings.LastIndexByte(key, '@')
	if at <= 0 {
		return "", "", false
	}
	name, version = key[:at], pnpmVersion(key[at+1:])
	if name == "" || version == "" {
		return "", "", false
	}
	return name, version, true
}

// --- Cargo.lock ---

// CargoLock parses Cargo's lockfile.
type CargoLock struct{}

// Name identifies the format.
func (CargoLock) Name() string { return "Cargo.lock" }

// Matches reports whether the file is a Cargo.lock.
func (CargoLock) Matches(filePath string) bool { return path.Base(filePath) == "Cargo.lock" }

func (CargoLock) lockfile() {}

// Parse maps every locked crate. Entries with no source are the workspace's
// own crates, which are published nowhere.
func (CargoLock) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var f struct {
		Package []struct {
			Name    string `toml:"name"`
			Version string `toml:"version"`
			Source  string `toml:"source"`
		} `toml:"package"`
	}
	if _, err := toml.Decode(string(content), &f); err != nil {
		return model.RepositorySnapshot{}, fmt.Errorf("manifest: parse %s: %w", filePath, err)
	}
	var snapshot model.RepositorySnapshot
	for _, p := range f.Package {
		if p.Name == "" || p.Version == "" || p.Source == "" {
			continue
		}
		snapshot.Dependencies = append(snapshot.Dependencies, locked("cargo", p.Name, p.Version, false, filePath))
	}
	return snapshot, nil
}

// --- poetry.lock ---

// PoetryLock parses Poetry's lockfile.
type PoetryLock struct{}

// Name identifies the format.
func (PoetryLock) Name() string { return "poetry.lock" }

// Matches reports whether the file is a poetry.lock.
func (PoetryLock) Matches(filePath string) bool { return path.Base(filePath) == "poetry.lock" }

func (PoetryLock) lockfile() {}

// Parse maps every locked package.
func (PoetryLock) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var f struct {
		Package []struct {
			Name    string `toml:"name"`
			Version string `toml:"version"`
		} `toml:"package"`
	}
	if _, err := toml.Decode(string(content), &f); err != nil {
		return model.RepositorySnapshot{}, fmt.Errorf("manifest: parse %s: %w", filePath, err)
	}
	var snapshot model.RepositorySnapshot
	for _, p := range f.Package {
		if p.Name == "" || p.Version == "" {
			continue
		}
		snapshot.Dependencies = append(snapshot.Dependencies, locked("pypi", pypiName(p.Name), p.Version, false, filePath))
	}
	return snapshot, nil
}

// --- composer.lock ---

// ComposerLock parses Composer's lockfile.
type ComposerLock struct{}

// Name identifies the format.
func (ComposerLock) Name() string { return "composer.lock" }

// Matches reports whether the file is a composer.lock.
func (ComposerLock) Matches(filePath string) bool { return path.Base(filePath) == "composer.lock" }

func (ComposerLock) lockfile() {}

type composerLockPackage struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Parse maps the packages installed for production and for development.
func (ComposerLock) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var f struct {
		Packages    []composerLockPackage `json:"packages"`
		PackagesDev []composerLockPackage `json:"packages-dev"`
	}
	if err := json.Unmarshal(content, &f); err != nil {
		return model.RepositorySnapshot{}, fmt.Errorf("manifest: parse %s: %w", filePath, err)
	}
	var snapshot model.RepositorySnapshot
	add := func(packages []composerLockPackage, file string) {
		for _, p := range packages {
			if strings.Contains(p.Name, "/") && p.Version != "" {
				snapshot.Dependencies = append(snapshot.Dependencies,
					locked("packagist", strings.ToLower(p.Name), p.Version, false, file))
			}
		}
	}
	add(f.Packages, filePath)
	add(f.PackagesDev, filePath+" (dev)")
	return snapshot, nil
}
