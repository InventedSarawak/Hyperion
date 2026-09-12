package manifest

import (
	"fmt"
	"path"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// GoMod parses a Go module file.
//
// Parsing uses golang.org/x/mod/modfile rather than a hand-rolled scanner:
// go.mod has real syntax (block requires, replace and exclude directives, line
// comments) and the toolchain's own parser is the only one guaranteed to agree
// with the toolchain.
type GoMod struct{}

// Name identifies the format.
func (GoMod) Name() string { return "go.mod" }

// Matches reports whether the file is a go.mod.
func (GoMod) Matches(filePath string) bool { return path.Base(filePath) == "go.mod" }

// Parse maps a go.mod onto a snapshot. The module line becomes the published
// library; each require becomes a dependency, with "// indirect" recorded as
// not direct.
func (GoMod) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	// Strict parsing first: only it reads replace directives, which say which
	// requirements are the repository's own modules. Lax parsing (which skips
	// replace and exclude) is the fallback, so a directive from a newer Go
	// than ours does not cost the whole dependency list.
	file, err := modfile.Parse(filePath, content, nil)
	if err != nil {
		lax, laxErr := modfile.ParseLax(filePath, content, nil)
		if laxErr != nil {
			return model.RepositorySnapshot{}, fmt.Errorf("manifest: parse %s: %w", filePath, laxErr)
		}
		file = lax
	}

	snapshot := model.RepositorySnapshot{}
	if file.Module != nil && file.Module.Mod.Path != "" {
		snapshot.Publishes = valueobject.NewPackageRef("go", file.Module.Mod.Path, "")
	}

	// A requirement replaced by a directory and never published — its version
	// is the v0.0.0 placeholder the go command writes for such modules — is one
	// of the repository's own modules: a monorepo wiring its services
	// together, not a dependency on anything published. A real release
	// replaced by a local copy (a vendored fork) is still recorded.
	local := map[string]bool{}
	for _, r := range file.Replace {
		if r != nil && modfile.IsDirectoryPath(r.New.Path) {
			local[r.Old.Path] = true
		}
	}

	for _, req := range file.Require {
		if req == nil || req.Mod.Path == "" || local[req.Mod.Path] && strings.HasPrefix(req.Mod.Version, "v0.0.0-") {
			continue
		}
		snapshot.Dependencies = append(snapshot.Dependencies,
			dependency("go", req.Mod.Path, req.Mod.Version, !req.Indirect, filePath))
	}
	return snapshot, nil
}
