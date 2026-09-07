package model

import (
	"time"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"
)

// RepositorySnapshot is what one read of a repository's manifests observed:
// the repository, who owns it, and everything it required at that moment. It
// is the aggregate the dependency-ingest use case operates on, so a manifest
// is applied to the graph as a single consistent unit rather than edge by edge.
type RepositorySnapshot struct {
	Repository Repository
	Author     Author
	// Publishes is the library this repository itself ships, when the manifest
	// declares one (go.mod's "module" line, package.json's "name"). It is what
	// turns a wall of repository-to-library edges into a connected graph: the
	// repository's own direct requirements are also that library's
	// requirements, so a traversal can keep walking past it.
	Publishes    valueobject.PackageRef
	Dependencies []Dependency
	ObservedAt   time.Time
}

// Validate enforces the aggregate's invariants. The repository must identify
// itself; individual dependencies are checked by ValidDependencies, since one
// unparseable line in a manifest should not discard the whole file.
func (s RepositorySnapshot) Validate() error { return s.Repository.Validate() }

// PublishedLibrary returns the library this repository ships, and whether it
// declares one at all. A repository that publishes nothing (an application,
// or a manifest we could not read a name from) is still perfectly valid.
func (s RepositorySnapshot) PublishedLibrary() (Library, bool) {
	if s.Publishes.Validate() != nil {
		return Library{}, false
	}
	return NewLibrary(s.Publishes), true
}

// DirectDependencies returns the subset of valid dependencies the repository
// declares itself, excluding any self-reference. These, and only these, are
// the published library's own requirements: a transitive dependency belongs
// to whichever library actually pulled it in, not to this one.
func (s RepositorySnapshot) DirectDependencies() []Dependency {
	published, hasPublished := s.PublishedLibrary()

	out := make([]Dependency, 0, len(s.Dependencies))
	for _, d := range s.ValidDependencies() {
		if !d.Direct {
			continue
		}
		if hasPublished && d.Library() == published {
			continue // a module never depends on itself
		}
		out = append(out, d)
	}
	return out
}

// ValidDependencies returns the dependencies worth writing, dropping any that
// fail their own invariants and collapsing duplicates. A manifest can name the
// same library twice (different constraint syntax, or once direct and once
// indirect); the graph holds one edge, and a direct declaration wins because
// it is the stronger statement about the repository's own code.
func (s RepositorySnapshot) ValidDependencies() []Dependency {
	seen := make(map[string]int, len(s.Dependencies))
	out := make([]Dependency, 0, len(s.Dependencies))

	for _, d := range s.Dependencies {
		if d.Validate() != nil {
			continue
		}
		if at, ok := seen[d.Package.Key()]; ok {
			if d.Direct && !out[at].Direct {
				out[at] = d
			}
			continue
		}
		seen[d.Package.Key()] = len(out)
		out = append(out, d)
	}
	return out
}
