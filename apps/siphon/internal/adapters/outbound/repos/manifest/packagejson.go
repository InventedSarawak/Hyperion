package manifest

import (
	"encoding/json"
	"fmt"
	"path"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// PackageJSON parses an npm package manifest. It is also how most Solidity
// projects built with Hardhat declare OpenZeppelin and friends.
type PackageJSON struct{}

// Name identifies the format.
func (PackageJSON) Name() string { return "package.json" }

// Matches reports whether the file is a package.json.
func (PackageJSON) Matches(filePath string) bool { return path.Base(filePath) == "package.json" }

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
func (PackageJSON) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var pkg packageJSON
	if err := json.Unmarshal(content, &pkg); err != nil {
		return model.RepositorySnapshot{}, fmt.Errorf("manifest: parse %s: %w", filePath, err)
	}

	snapshot := model.RepositorySnapshot{}
	if pkg.Name != "" && !pkg.Private {
		snapshot.Publishes = valueobject.NewPackageRef("npm", pkg.Name, "")
	}
	snapshot.Dependencies = append(snapshot.Dependencies,
		toDependencies("npm", pkg.Dependencies, true, filePath)...)
	snapshot.Dependencies = append(snapshot.Dependencies,
		toDependencies("npm", pkg.DevDependencies, false, filePath+" (dev)")...)
	return snapshot, nil
}

// toDependencies maps a name -> constraint block, in name order.
func toDependencies(ecosystem string, entries map[string]string, direct bool, file string) []model.Dependency {
	out := make([]model.Dependency, 0, len(entries))
	for _, name := range sortedKeys(entries) {
		out = append(out, dependency(ecosystem, name, entries[name], direct, file))
	}
	return out
}
