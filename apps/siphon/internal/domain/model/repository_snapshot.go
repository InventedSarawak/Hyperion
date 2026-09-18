package model

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// Repository is a source repository siphon reads manifests from.
type Repository struct {
	Owner         string
	Name          string
	URL           string
	DefaultBranch string
}

// ErrMissingRepositoryIdentity is returned when owner or name is absent.
var ErrMissingRepositoryIdentity = errors.New("repository: owner and name are required")

// Validate enforces the entity's invariants.
func (r Repository) Validate() error {
	if strings.TrimSpace(r.Owner) == "" || strings.TrimSpace(r.Name) == "" {
		return ErrMissingRepositoryIdentity
	}
	return nil
}

// FullName is the canonical identity, e.g. "gin-gonic/gin".
func (r Repository) FullName() string { return fmt.Sprintf("%s/%s", r.Owner, r.Name) }

// Author is whoever owns a repository — a person or an organization.
type Author struct {
	Login string
	Name  string
	URL   string
}

// IsZero reports whether the author is absent. Ownership is optional.
func (a Author) IsZero() bool { return strings.TrimSpace(a.Login) == "" }

// Dependency is one requirement declared by a manifest.
//
// Direct answers a specific question: does this requirement flow through to
// whoever consumes what the repository publishes? A go.mod "// indirect" entry
// and a package.json devDependency both answer no — the repository is still
// exposed to them, but a downstream consumer is not.
type Dependency struct {
	Package      valueobject.PackageRef
	Direct       bool
	ManifestPath string
	// Locked marks a version read from a lockfile: the one actually
	// installed, rather than the range a manifest allows.
	Locked bool
	// DependsOn is what this package itself requires, when the file says.
	//
	// A lockfile is a graph, not a list: it records which package pulled in
	// which. Manifests carry no such thing — package.json names what the
	// project asked for and nothing about what those ask for in turn — so
	// this is empty for them, and empty is "not stated", never "nothing".
	//
	// Without it a repository's thousand transitive packages all hang
	// directly off the repository, and the answer to "how does this CVE
	// reach me?" is a list rather than a path.
	DependsOn []valueobject.PackageRef
}

// Validate enforces the entity's invariants.
func (d Dependency) Validate() error { return d.Package.Validate() }

// RepositorySnapshot is one read of a repository's manifests: what it is, who
// owns it, what it publishes, and what it requires.
type RepositorySnapshot struct {
	Repository Repository
	Author     Author
	// Publishes is the library this repository itself ships, read from the
	// manifest (go.mod's "module" line, package.json's "name").
	Publishes    valueobject.PackageRef
	Dependencies []Dependency
	ObservedAt   time.Time
}

// Validate enforces the aggregate's invariants. Dependencies are not checked
// here: one unparseable line should not discard a whole manifest.
func (s RepositorySnapshot) Validate() error { return s.Repository.Validate() }

// DependencyEdge is one package requiring another, as a lockfile recorded it.
type DependencyEdge struct {
	From valueobject.PackageRef
	To   valueobject.PackageRef
}

// DependencyEdges is every package-to-package requirement in the snapshot,
// deduplicated and in a stable order.
//
// Only edges whose far end is also in the snapshot are reported. A lockfile
// lists a package's requirements by name, including ones it did not resolve
// itself — an optional peer, a platform-specific build — and an edge to a
// package nothing installed would invent a dependency that is not there.
func (s RepositorySnapshot) DependencyEdges() []DependencyEdge {
	known := make(map[string]valueobject.PackageRef, len(s.Dependencies))
	for _, d := range s.Dependencies {
		if d.Package.Validate() == nil {
			known[localKey(d.Package)] = d.Package
		}
	}

	seen := make(map[string]struct{}, len(known))
	var out []DependencyEdge
	for _, d := range s.Dependencies {
		if d.Package.Validate() != nil {
			continue
		}
		from := localKey(d.Package)
		for _, ref := range d.DependsOn {
			to, ok := known[localKey(ref)]
			if !ok || localKey(to) == from {
				continue
			}
			pair := from + ">" + localKey(to)
			if _, dup := seen[pair]; dup {
				continue
			}
			seen[pair] = struct{}{}
			out = append(out, DependencyEdge{From: d.Package, To: to})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := localKey(out[i].From), localKey(out[j].From); a != b {
			return a < b
		}
		return localKey(out[i].To) < localKey(out[j].To)
	})
	return out
}

// localKey identifies a package within one snapshot, for matching an entry's
// stated requirement to the entry that resolved it. It is deliberately not
// the graph's key: cortex owns that, because it owns the per-ecosystem name
// rules. Case is folded because a lockfile can spell the same package two
// ways — NuGet writes "Newtonsoft.Json" in one place and "newtonsoft.json" in
// another — and the two must still meet.
func localKey(p valueobject.PackageRef) string {
	return p.Ecosystem.String() + ":" + strings.ToLower(strings.TrimSpace(p.Name))
}

// Merge folds another manifest's findings into this snapshot. A repository can
// declare several manifests (a Go service with a JavaScript front end), and
// each read contributes what it knows: the first published module wins, and
// dependencies accumulate.
func (s RepositorySnapshot) Merge(other RepositorySnapshot) RepositorySnapshot {
	if s.Publishes.IsZero() {
		s.Publishes = other.Publishes
	}
	if s.Author.IsZero() {
		s.Author = other.Author
	}
	s.Dependencies = append(s.Dependencies, other.Dependencies...)
	return s
}
