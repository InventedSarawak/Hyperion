package model

import "time"

// RepositorySnapshot is what one read of a repository's manifests observed:
// the repository, who owns it, and everything it required at that moment. It
// is the aggregate the dependency-ingest use case operates on, so a manifest
// is applied to the graph as a single consistent unit rather than edge by edge.
type RepositorySnapshot struct {
	Repository   Repository
	Author       Author
	Dependencies []Dependency
	ObservedAt   time.Time
}

// Validate enforces the aggregate's invariants. The repository must identify
// itself; individual dependencies are checked by ValidDependencies, since one
// unparseable line in a manifest should not discard the whole file.
func (s RepositorySnapshot) Validate() error { return s.Repository.Validate() }

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
