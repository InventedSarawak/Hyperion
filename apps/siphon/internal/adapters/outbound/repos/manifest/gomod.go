package manifest

import (
	"fmt"

	"golang.org/x/mod/modfile"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// GoModPath is the manifest file this parser reads.
const GoModPath = "go.mod"

// GoMod parses a Go module file.
//
// Parsing uses golang.org/x/mod/modfile rather than a hand-rolled scanner:
// go.mod has real syntax (block requires, replace and exclude directives, line
// comments) and the toolchain's own parser is the only one guaranteed to agree
// with the toolchain.
type GoMod struct{}

// Path reports the file this parser expects.
func (GoMod) Path() string { return GoModPath }

// Parse maps a go.mod onto a snapshot. The module line becomes the published
// library; each require becomes a dependency, with "// indirect" recorded as
// not direct.
func (GoMod) Parse(content []byte) (model.RepositorySnapshot, error) {
	// Lax parsing: a replace directive pointing at a local path, or a
	// toolchain line from a newer Go than ours, must not cost us the whole
	// dependency list.
	file, err := modfile.ParseLax(GoModPath, content, nil)
	if err != nil {
		return model.RepositorySnapshot{}, fmt.Errorf("manifest: parse go.mod: %w", err)
	}

	snapshot := model.RepositorySnapshot{}
	if file.Module != nil && file.Module.Mod.Path != "" {
		snapshot.Publishes = valueobject.NewPackageRef("go", file.Module.Mod.Path, "")
	}

	for _, req := range file.Require {
		if req == nil || req.Mod.Path == "" {
			continue
		}
		snapshot.Dependencies = append(snapshot.Dependencies, model.Dependency{
			Package:      valueobject.NewPackageRef("go", req.Mod.Path, req.Mod.Version),
			Direct:       !req.Indirect,
			ManifestPath: GoModPath,
		})
	}
	return snapshot, nil
}
