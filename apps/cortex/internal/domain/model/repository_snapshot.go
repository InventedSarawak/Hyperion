package model

import (
	"sort"
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

// LibraryEdge is one library requiring another, as a lockfile recorded it.
type LibraryEdge struct {
	From Library
	To   Library
}

// LibraryEdges is every library-to-library requirement this snapshot observed,
// deduplicated and in a stable order.
//
// Only edges whose far end is also in the snapshot are reported. A lockfile
// states a package's requirements by name, including ones it did not resolve
// itself — an optional peer, a platform-specific build — and an edge to a
// library nothing installed would invent a dependency that is not there.
//
// This is what makes the graph transitive for every library, not only for the
// one a tracked repository happens to publish.
func (s RepositorySnapshot) LibraryEdges() []LibraryEdge {
	deps := s.ValidDependencies()
	known := make(map[string]Library, len(deps))
	for _, d := range deps {
		known[d.Library().Key()] = d.Library()
	}

	seen := make(map[string]struct{}, len(known))
	out := make([]LibraryEdge, 0, len(known))
	for _, d := range deps {
		from := d.Library()
		for _, ref := range d.DependsOn {
			to, ok := known[NewLibrary(ref).Key()]
			if !ok || to.Key() == from.Key() {
				continue
			}
			pair := from.Key() + ">" + to.Key()
			if _, dup := seen[pair]; dup {
				continue
			}
			seen[pair] = struct{}{}
			out = append(out, LibraryEdge{From: from, To: to})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From.Key() != out[j].From.Key() {
			return out[i].From.Key() < out[j].From.Key()
		}
		return out[i].To.Key() < out[j].To.Key()
	})
	return out
}

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
// fail their own invariants and collapsing duplicates. A repository can name
// the same library twice — in two manifests, or in a manifest and the lockfile
// beside it — and the graph holds one edge; mergeDependency decides which
// declaration it carries.
// mergeDependency folds a second declaration of one library into the first.
// A locked version wins over a declared range, because it is what is actually
// installed and can be judged outright; failing that, a direct declaration
// wins over an indirect one, being the stronger statement about the
// repository's own code. The flags are the union either way: a library reached
// both directly and transitively is still a direct dependency.
func mergeDependency(kept, next Dependency) Dependency {
	winner := kept
	switch {
	case next.Locked && !kept.Locked:
		winner = next
	case next.Direct && !kept.Direct && next.Locked == kept.Locked:
		winner = next
	}
	winner.Direct = kept.Direct || next.Direct
	winner.Locked = kept.Locked || next.Locked
	// Requirements are the union: two manifests can each report part of what
	// a package needs, and the graph wants every edge either one saw.
	winner.DependsOn = unionRefs(kept.DependsOn, next.DependsOn)
	return winner
}

// unionRefs merges two requirement lists, keeping the first spelling of each.
func unionRefs(a, b []valueobject.PackageRef) []valueobject.PackageRef {
	if len(a) == 0 {
		return b
	}
	if len(b) == 0 {
		return a
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	out := make([]valueobject.PackageRef, 0, len(a)+len(b))
	for _, ref := range append(append([]valueobject.PackageRef{}, a...), b...) {
		if _, dup := seen[ref.Key()]; dup {
			continue
		}
		seen[ref.Key()] = struct{}{}
		out = append(out, ref)
	}
	return out
}

func (s RepositorySnapshot) ValidDependencies() []Dependency {
	seen := make(map[string]int, len(s.Dependencies))
	out := make([]Dependency, 0, len(s.Dependencies))

	for _, d := range s.Dependencies {
		if d.Validate() != nil {
			continue
		}
		if at, ok := seen[d.Package.Key()]; ok {
			out[at] = mergeDependency(out[at], d)
			continue
		}
		seen[d.Package.Key()] = len(out)
		out = append(out, d)
	}
	return out
}
