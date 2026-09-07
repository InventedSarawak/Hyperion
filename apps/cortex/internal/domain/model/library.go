package model

import (
	"errors"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// Library is a package as it appears in the graph: one node per ecosystem and
// name. The version a given repository pins is a property of the dependency
// edge, not of the library, so that every dependant of "npm:lodash" converges
// on the same node and a traversal can find them all at once.
type Library struct {
	Ecosystem valueobject.Ecosystem
	Name      string
}

// ErrMissingLibraryName is returned when a library has no name.
var ErrMissingLibraryName = errors.New("library: name is required")

// NewLibrary derives the graph node from a package reference, discarding the
// version.
func NewLibrary(ref valueobject.PackageRef) Library {
	return Library{Ecosystem: ref.Ecosystem, Name: ref.Name}
}

// Validate enforces the entity's invariants.
func (l Library) Validate() error {
	if strings.TrimSpace(l.Name) == "" {
		return ErrMissingLibraryName
	}
	return nil
}

// Key is the graph identity, e.g. "npm:lodash".
func (l Library) Key() string {
	return valueobject.PackageRef{Ecosystem: l.Ecosystem, Name: l.Name}.Key()
}

// Dependency is one requirement declared by a repository's manifest.
type Dependency struct {
	Package      valueobject.PackageRef
	Direct       bool   // false for transitive requirements (go.mod "// indirect")
	ManifestPath string // where it was declared, e.g. "go.mod"
}

// Validate enforces the entity's invariants.
func (d Dependency) Validate() error { return d.Package.Validate() }

// Library returns the graph node this dependency points at.
func (d Dependency) Library() Library { return NewLibrary(d.Package) }
