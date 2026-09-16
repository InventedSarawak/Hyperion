package model

import (
	"errors"
	"fmt"
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
