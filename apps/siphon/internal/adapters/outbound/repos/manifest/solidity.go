package manifest

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
)

// Solidity has no registry of its own. Contracts import libraries — above
// all OpenZeppelin — that are published to npm, and advisories name them
// there: npm:@openzeppelin/contracts. A project pulls them in one of three
// ways, and each is read as the npm package it vendors:
//
//   - package.json (Hardhat, Truffle): an ordinary npm dependency;
//   - a git submodule under lib/ (Foundry's default): the repository adapter
//     reads the library's own version file at the pinned commit;
//   - Soldeer, Foundry's package manager: [dependencies] in foundry.toml.

// soldeerPackages maps Soldeer names onto the npm packages advisories use.
var soldeerPackages = map[string]string{
	"@openzeppelin-contracts":             "@openzeppelin/contracts",
	"@openzeppelin-contracts-upgradeable": "@openzeppelin/contracts-upgradeable",
}

// Foundry parses the Soldeer dependencies in foundry.toml.
type Foundry struct{}

// Name identifies the format.
func (Foundry) Name() string { return "foundry.toml" }

// Matches reports whether the file is a foundry.toml.
func (Foundry) Matches(filePath string) bool { return path.Base(filePath) == "foundry.toml" }

// Parse maps the libraries advisories know by an npm name. Others have no
// advisories anywhere to match, and are left out rather than recorded under
// a name nothing uses.
func (Foundry) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var f struct {
		Dependencies map[string]any `toml:"dependencies"`
	}
	if _, err := toml.Decode(string(content), &f); err != nil {
		return model.RepositorySnapshot{}, fmt.Errorf("manifest: parse %s: %w", filePath, err)
	}
	var snapshot model.RepositorySnapshot
	for _, name := range sortedKeys(f.Dependencies) {
		npm, known := soldeerPackages[strings.ToLower(name)]
		if !known {
			continue
		}
		version, _ := tableVersion(f.Dependencies[name])
		snapshot.Dependencies = append(snapshot.Dependencies, dependency("npm", npm, version, true, filePath+" (soldeer)"))
	}
	return snapshot, nil
}

// Submodule is one git submodule: where it sits in the repository, and where
// its code comes from.
type Submodule struct{ Path, URL string }

// ParseGitmodules reads a .gitmodules file.
func ParseGitmodules(content []byte) []Submodule {
	var out []Submodule
	current := -1
	for _, raw := range strings.Split(strings.ReplaceAll(string(content), "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if strings.HasPrefix(line, "[submodule") {
			out = append(out, Submodule{})
			current = len(out) - 1
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || current < 0 {
			continue
		}
		switch strings.TrimSpace(key) {
		case "path":
			out[current].Path = strings.TrimSpace(value)
		case "url":
			out[current].URL = strings.TrimSpace(value)
		}
	}
	kept := out[:0]
	for _, s := range out {
		if s.Path != "" && s.URL != "" {
			kept = append(kept, s)
		}
	}
	return kept
}

// SubmoduleSource is the GitHub repository a submodule vendors, and the file
// in it — read at the pinned commit — that names the package and version.
type SubmoduleSource struct {
	Owner, Repo string
	VersionFile string
	// Package, when set, is the npm name to record, overriding the file's.
	Package string
}

var githubRemote = regexp.MustCompile(`(?i)github\.com[/:]([^/\s]+)/([^/\s]+?)(?:\.git)?/?$`)

// knownSubmodules are libraries whose npm package lives in a subdirectory of
// their repository rather than at its root.
var knownSubmodules = map[string]SubmoduleSource{
	"openzeppelin/openzeppelin-contracts":             {VersionFile: "contracts/package.json", Package: "@openzeppelin/contracts"},
	"openzeppelin/openzeppelin-contracts-upgradeable": {VersionFile: "contracts/package.json", Package: "@openzeppelin/contracts-upgradeable"},
}

// SourceOf says where a submodule's version can be read. Submodules hosted
// anywhere but GitHub report false.
func SourceOf(remote string) (SubmoduleSource, bool) {
	m := githubRemote.FindStringSubmatch(strings.TrimSpace(remote))
	if m == nil {
		return SubmoduleSource{}, false
	}
	src := SubmoduleSource{Owner: m[1], Repo: m[2], VersionFile: "package.json"}
	if known, ok := knownSubmodules[strings.ToLower(m[1]+"/"+m[2])]; ok {
		src.VersionFile, src.Package = known.VersionFile, known.Package
	}
	return src, true
}

// ReadPackageVersion reads the name and version a package.json declares.
func ReadPackageVersion(content []byte) (name, version string, ok bool) {
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if json.Unmarshal(content, &pkg) != nil || pkg.Name == "" || pkg.Version == "" {
		return "", "", false
	}
	return pkg.Name, pkg.Version, true
}
