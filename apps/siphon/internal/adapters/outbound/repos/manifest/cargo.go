package manifest

import (
	"fmt"
	"path"

	"github.com/BurntSushi/toml"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// Cargo parses a Rust manifest, Cargo.toml.
type Cargo struct{}

// Name identifies the format.
func (Cargo) Name() string { return "Cargo.toml" }

// Matches reports whether the file is a Cargo.toml.
func (Cargo) Matches(filePath string) bool { return path.Base(filePath) == "Cargo.toml" }

type cargoTables struct {
	Dependencies      map[string]any `toml:"dependencies"`
	DevDependencies   map[string]any `toml:"dev-dependencies"`
	BuildDependencies map[string]any `toml:"build-dependencies"`
}

type cargoFile struct {
	Package struct {
		Name string `toml:"name"`
	} `toml:"package"`
	Dependencies      map[string]any         `toml:"dependencies"`
	DevDependencies   map[string]any         `toml:"dev-dependencies"`
	BuildDependencies map[string]any         `toml:"build-dependencies"`
	Target            map[string]cargoTables `toml:"target"`
	Workspace         struct {
		Dependencies map[string]any `toml:"dependencies"`
	} `toml:"workspace"`
}

// Parse maps the dependency tables — including per-target ones and a
// workspace's shared declarations — onto a snapshot. Dev and build
// dependencies are recorded as indirect.
func (Cargo) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var f cargoFile
	if _, err := toml.Decode(string(content), &f); err != nil {
		return model.RepositorySnapshot{}, fmt.Errorf("manifest: parse %s: %w", filePath, err)
	}
	var snapshot model.RepositorySnapshot
	if f.Package.Name != "" {
		snapshot.Publishes = valueobject.NewPackageRef("cargo", f.Package.Name, "")
	}
	add := func(entries map[string]any, direct bool, file string) {
		for _, name := range sortedKeys(entries) {
			if crate, version, ok := cargoDependency(name, entries[name], f.Workspace.Dependencies); ok {
				snapshot.Dependencies = append(snapshot.Dependencies, dependency("cargo", crate, version, direct, file))
			}
		}
	}
	add(f.Workspace.Dependencies, true, filePath)
	add(f.Dependencies, true, filePath)
	add(f.DevDependencies, false, filePath+" (dev)")
	add(f.BuildDependencies, false, filePath+" (build)")
	for _, target := range sortedKeys(f.Target) {
		t := f.Target[target]
		add(t.Dependencies, true, filePath)
		add(t.DevDependencies, false, filePath+" (dev)")
		add(t.BuildDependencies, false, filePath+" (build)")
	}
	return snapshot, nil
}

// cargoDependency reads one entry: "1.2", or a table that may rename the
// crate, point at a local path (the workspace's own crate, skipped), or defer
// to the workspace's declaration.
func cargoDependency(name string, v any, workspace map[string]any) (crate, version string, ok bool) {
	switch t := v.(type) {
	case string:
		return name, t, true
	case map[string]any:
		crate = name
		if pkg, isString := t["package"].(string); isString && pkg != "" {
			crate = pkg
		}
		if inherit, _ := t["workspace"].(bool); inherit {
			if w, found := workspace[name]; found {
				_, version, _ = cargoDependency(name, w, nil)
			}
			return crate, version, true
		}
		version, _ = t["version"].(string)
		if _, local := t["path"]; local && version == "" {
			return "", "", false
		}
		return crate, version, true
	}
	return "", "", false
}
