package manifest

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// PackageJSONPath is the manifest file this parser reads.
const PackageJSONPath = "package.json"

// PackageJSON parses an npm package manifest.
type PackageJSON struct{}

// Path reports the file this parser expects.
func (PackageJSON) Path() string { return PackageJSONPath }

// packageJSON is the wire shape, trimmed to the fields we map.
type packageJSON struct {
	Name            string            `json:"name"`
	Private         bool              `json:"private"`
	Dependencies    map[string]string `json:"dependencies"`
	DevDependencies map[string]string `json:"devDependencies"`
}

// Parse maps a package.json onto a snapshot.
//
// Runtime dependencies are direct: they reach anyone who installs this
// package. devDependencies are recorded too — a compromised build-time package
// is a genuine exposure for this repository — but as indirect, because they
// are not inflicted on consumers.
//
// A private package publishes nothing, so its name is not recorded as a
// library: nothing can ever depend on it.
func (PackageJSON) Parse(content []byte) (model.RepositorySnapshot, error) {
	var pkg packageJSON
	if err := json.Unmarshal(content, &pkg); err != nil {
		return model.RepositorySnapshot{}, fmt.Errorf("manifest: parse package.json: %w", err)
	}

	snapshot := model.RepositorySnapshot{}
	if pkg.Name != "" && !pkg.Private {
		snapshot.Publishes = valueobject.NewPackageRef("npm", pkg.Name, "")
	}

	snapshot.Dependencies = append(snapshot.Dependencies,
		toDependencies(pkg.Dependencies, true, PackageJSONPath)...)
	snapshot.Dependencies = append(snapshot.Dependencies,
		toDependencies(pkg.DevDependencies, false, PackageJSONPath+" (dev)")...)
	return snapshot, nil
}

// toDependencies maps a name -> constraint block. The names are sorted because
// Go randomizes map iteration: without this, two reads of an unchanged
// manifest would produce differently ordered logs and diffs for no reason.
func toDependencies(entries map[string]string, direct bool, manifestPath string) []model.Dependency {
	names := make([]string, 0, len(entries))
	for name := range entries {
		if name != "" {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	out := make([]model.Dependency, 0, len(names))
	for _, name := range names {
		out = append(out, model.Dependency{
			Package:      valueobject.NewPackageRef("npm", name, entries[name]),
			Direct:       direct,
			ManifestPath: manifestPath,
		})
	}
	return out
}
