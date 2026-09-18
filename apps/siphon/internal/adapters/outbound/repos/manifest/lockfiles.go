package manifest

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/BurntSushi/toml"
	"go.yaml.in/yaml/v3"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
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

// requires records what a locked package itself depends on, by name. The
// versions are the ranges the package asked for, not what was installed, so
// only the names are kept: the installed version is on the other entry, which
// is where the snapshot reads it from.
func requires(ecosystem string, names ...string) []valueobject.PackageRef {
	refs := make([]valueobject.PackageRef, 0, len(names))
	for _, name := range names {
		if name = strings.TrimSpace(name); name != "" {
			refs = append(refs, valueobject.NewPackageRef(ecosystem, name, ""))
		}
	}
	return refs
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
		dep := locked("npm", name, entry.Version, direct[name] && !entry.Dev, filePath)
		dep.DependsOn = requires("npm", sortedKeys(entry.Deps)...)
		snapshot.Dependencies = append(snapshot.Dependencies, dep)
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
		// A package's own requirements moved to "snapshots" in lockfile v9;
		// before that they sat on the "packages" entry. Both are read, and a
		// file only ever has one of them.
		Packages  map[string]pnpmPackage `yaml:"packages"`
		Snapshots map[string]pnpmPackage `yaml:"snapshots"`
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
		name, version, ok := pnpmPackageKey(key)
		if !ok {
			continue
		}
		dep := locked("npm", name, version, false, filePath)
		dep.DependsOn = pnpmRequires(f.Packages[key], f.Snapshots[key])
		snapshot.Dependencies = append(snapshot.Dependencies, dep)
	}
	return snapshot, nil
}

// pnpmPackage is one resolved package's own requirements.
type pnpmPackage struct {
	Dependencies         map[string]string `yaml:"dependencies"`
	OptionalDependencies map[string]string `yaml:"optionalDependencies"`
}

// pnpmRequires is what a package needs, from wherever this lockfile version
// keeps it. Peer dependencies are left out: the consumer installs those, not
// this package, so an edge from here would point the wrong way.
func pnpmRequires(entries ...pnpmPackage) []valueobject.PackageRef {
	var names []string
	for _, e := range entries {
		names = append(names, sortedKeys(e.Dependencies)...)
		names = append(names, sortedKeys(e.OptionalDependencies)...)
	}
	return requires("npm", names...)
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
			Name    string   `toml:"name"`
			Version string   `toml:"version"`
			Source  string   `toml:"source"`
			Deps    []string `toml:"dependencies"`
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
		dep := locked("cargo", p.Name, p.Version, false, filePath)
		// Cargo writes a requirement as "name", "name version", or
		// "name version (source)" — only the name identifies the crate.
		names := make([]string, 0, len(p.Deps))
		for _, raw := range p.Deps {
			names = append(names, strings.Fields(raw)[0])
		}
		dep.DependsOn = requires("cargo", names...)
		snapshot.Dependencies = append(snapshot.Dependencies, dep)
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
			Name    string         `toml:"name"`
			Version string         `toml:"version"`
			Deps    map[string]any `toml:"dependencies"`
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
		dep := locked("pypi", pypiName(p.Name), p.Version, false, filePath)
		// The value is a version string, a table of constraints, or a list of
		// either — all of them describing the same named package, which is
		// the only part an edge needs.
		names := make([]string, 0, len(p.Deps))
		for _, name := range sortedKeys(p.Deps) {
			names = append(names, pypiName(name))
		}
		dep.DependsOn = requires("pypi", names...)
		snapshot.Dependencies = append(snapshot.Dependencies, dep)
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
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Require map[string]string `json:"require"`
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
			if !strings.Contains(p.Name, "/") || p.Version == "" {
				continue
			}
			dep := locked("packagist", strings.ToLower(p.Name), p.Version, false, file)
			// "require" also holds platform constraints — php, ext-json,
			// lib-* — which name no package. Those resolve to nothing in the
			// snapshot and are dropped when the edges are built.
			dep.DependsOn = requires("packagist", sortedKeys(p.Require)...)
			snapshot.Dependencies = append(snapshot.Dependencies, dep)
		}
	}
	add(f.Packages, filePath)
	add(f.PackagesDev, filePath+" (dev)")
	return snapshot, nil
}

// --- npm: yarn.lock ---

// YarnLock parses yarn.lock, both the classic (v1) format and the YAML-ish
// Berry (v2+) one.
//
// Its own format, not YAML, despite the resemblance: a v1 file has bare
// `name@range:` headers and indented `version "1.2.3"` lines, and a YAML parser
// rejects it. Both versions share the shape this reads — an entry header naming
// one or more descriptors, then a version line — so one line-oriented reader
// handles both rather than two parsers guessing which they have.
type YarnLock struct{}

// Name identifies the format.
func (YarnLock) Name() string { return "yarn.lock" }

// Matches reports whether the file is a yarn.lock.
func (YarnLock) Matches(filePath string) bool { return path.Base(filePath) == "yarn.lock" }

func (YarnLock) lockfile() {}

// Parse maps every installed package to the version it resolved to.
//
// Every entry is reported, including transitive ones — that is the point of
// reading a lockfile — and none is marked direct, because yarn.lock does not
// say which are. package.json beside it does, and the two are merged.
func (YarnLock) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var (
		snapshot model.RepositorySnapshot
		resolved = map[string]string{}   // name -> the version it resolved to
		children = map[string][]string{} // name -> what that package requires
		names    []string
		inDeps   bool
		depth    int
	)

	for _, raw := range strings.Split(string(content), "\n") {
		line := strings.TrimRight(raw, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// An entry header is unindented and ends in a colon; everything under
		// it is indented.
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") {
			names, inDeps = yarnEntryNames(trimmed), false
			continue
		}
		if len(names) == 0 {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))

		// Inside a dependencies block, every line indented under it names one
		// requirement. The block ends at the first line that is not.
		if inDeps {
			if indent > depth {
				if child, ok := yarnChildName(trimmed); ok {
					for _, name := range names {
						children[name] = append(children[name], child)
					}
				}
				continue
			}
			inDeps = false
		}
		// Only "dependencies": a peer or a dev requirement is installed by
		// whoever consumes this package, not by this package, so an edge from
		// here would say something the lockfile does not.
		if trimmed == "dependencies:" {
			inDeps, depth = true, indent
			continue
		}
		if version, ok := yarnVersion(trimmed); ok {
			for _, name := range names {
				if _, done := resolved[name]; !done {
					resolved[name] = version
				}
			}
		}
	}

	for _, name := range sortedKeys(resolved) {
		dep := locked("npm", name, resolved[name], false, filePath)
		dep.DependsOn = requires("npm", children[name]...)
		snapshot.Dependencies = append(snapshot.Dependencies, dep)
	}
	return snapshot, nil
}

// yarnChildName reads the package name from one line of a dependencies block.
// v1 writes `name "range"`, Berry writes `name: range`, and either may quote a
// scoped name — hence unquoting on both sides of the colon.
func yarnChildName(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", false
	}
	name := strings.Trim(fields[0], `"'`)
	name = strings.Trim(strings.TrimSuffix(name, ":"), `"'`)
	return name, name != ""
}

// yarnEntryNames reads the package names out of an entry header.
//
// A header lists every descriptor that resolved to the same version, e.g.
//
//	"lodash@^4.17.0", "lodash@^4.17.21":
//
// so the names are the parts before the last @ of each descriptor — last,
// because a scoped package is itself "@scope/name".
func yarnEntryNames(header string) []string {
	header = strings.TrimSuffix(strings.TrimSpace(header), ":")
	if header == "" {
		return nil
	}

	var names []string
	seen := map[string]struct{}{}
	for _, descriptor := range strings.Split(header, ",") {
		descriptor = strings.Trim(strings.TrimSpace(descriptor), `"'`)
		if descriptor == "" {
			continue
		}
		at := strings.LastIndex(descriptor, "@")
		if at <= 0 {
			continue // no range, or a bare "@" — nothing nameable
		}
		name := strings.TrimSpace(descriptor[:at])
		if name == "" {
			continue
		}
		// A header lists every range that resolved here, and two ranges of
		// one package are one package: "lodash@^4.17.0, lodash@^4.17.21".
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	return names
}

// yarnVersion reads the resolved version from an entry's version line.
func yarnVersion(line string) (string, bool) {
	// v1 writes `version "1.2.3"`, Berry writes `version: 1.2.3`.
	rest, ok := strings.CutPrefix(line, "version")
	if !ok {
		return "", false
	}
	rest = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(rest), ":"))
	rest = strings.Trim(rest, `"'`)
	if rest == "" {
		return "", false
	}
	return rest, true
}

// --- NuGet: packages.lock.json ---

// PackagesLock parses NuGet's packages.lock.json.
type PackagesLock struct{}

// Name identifies the format.
func (PackagesLock) Name() string { return "packages.lock.json" }

// Matches reports whether the file is a packages.lock.json.
func (PackagesLock) Matches(filePath string) bool {
	return path.Base(filePath) == "packages.lock.json"
}

func (PackagesLock) lockfile() {}

// packagesLockEntry is one resolved package.
//
// "resolved" is the version actually restored. "requested" is the range the
// project asked for, which is what the .csproj already says — the lockfile is
// read precisely to get past that.
type packagesLockEntry struct {
	Type      string            `json:"type"`
	Resolved  string            `json:"resolved"`
	Requested string            `json:"requested"`
	Deps      map[string]string `json:"dependencies"`
}

// Parse maps every restored package, across every target framework.
//
// A project is often locked for several frameworks at once and the same
// package can resolve differently in each. Every resolution is reported: a
// version that is vulnerable on one framework is vulnerable, whichever other
// framework also builds.
func (PackagesLock) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var f struct {
		Dependencies map[string]map[string]packagesLockEntry `json:"dependencies"`
	}
	if err := json.Unmarshal(content, &f); err != nil {
		return model.RepositorySnapshot{}, fmt.Errorf("packages.lock.json %s: %w", filePath, err)
	}

	var (
		snapshot model.RepositorySnapshot
		seen     = map[string]bool{}
	)
	for _, framework := range sortedKeys(f.Dependencies) {
		packages := f.Dependencies[framework]
		for _, name := range sortedKeys(packages) {
			entry := packages[name]
			if entry.Resolved == "" {
				continue
			}
			// "Project" entries are sibling projects in the same solution,
			// not packages from a registry.
			if strings.EqualFold(entry.Type, "Project") {
				continue
			}
			key := name + "@" + entry.Resolved
			if seen[key] {
				continue
			}
			seen[key] = true

			// "Direct" is the lockfile's own word for what the project asked
			// for; "Transitive" came in through something else.
			direct := strings.EqualFold(entry.Type, "Direct")
			dep := locked("nuget", name, entry.Resolved, direct, filePath)
			dep.DependsOn = requires("nuget", sortedKeys(entry.Deps)...)
			snapshot.Dependencies = append(snapshot.Dependencies, dep)
		}
	}
	return snapshot, nil
}
