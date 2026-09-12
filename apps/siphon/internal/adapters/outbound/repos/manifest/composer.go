package manifest

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/model"
	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// Composer parses a PHP project's composer.json.
type Composer struct{}

// Name identifies the format.
func (Composer) Name() string { return "composer.json" }

// Matches reports whether the file is a composer.json.
func (Composer) Matches(filePath string) bool { return path.Base(filePath) == "composer.json" }

// Parse maps require and require-dev. Platform requirements — php itself,
// ext-*, lib-* — are not packages and are skipped; Packagist names are
// vendor/package, lower case.
func (Composer) Parse(filePath string, content []byte) (model.RepositorySnapshot, error) {
	var f struct {
		Name       string            `json:"name"`
		Require    map[string]string `json:"require"`
		RequireDev map[string]string `json:"require-dev"`
	}
	if err := json.Unmarshal(content, &f); err != nil {
		return model.RepositorySnapshot{}, fmt.Errorf("manifest: parse %s: %w", filePath, err)
	}
	var snapshot model.RepositorySnapshot
	if f.Name != "" {
		snapshot.Publishes = valueobject.NewPackageRef("packagist", strings.ToLower(f.Name), "")
	}
	add := func(entries map[string]string, direct bool, file string) {
		for _, name := range sortedKeys(entries) {
			if strings.Contains(name, "/") { // everything else is a platform requirement
				snapshot.Dependencies = append(snapshot.Dependencies,
					dependency("packagist", strings.ToLower(name), entries[name], direct, file))
			}
		}
	}
	add(f.Require, true, filePath)
	add(f.RequireDev, false, filePath+" (dev)")
	return snapshot, nil
}
