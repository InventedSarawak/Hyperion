package model

import (
	"errors"
	"fmt"
	"strings"
)

// Repository is a source repository whose dependency manifests cortex has
// read. Owner + Name is its identity; the rest is display detail.
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

// IsZero reports whether the repository names nothing.
func (r Repository) IsZero() bool { return r.Owner == "" && r.Name == "" }

// FullName is the graph identity, e.g. "kubernetes/kubernetes".
func (r Repository) FullName() string { return fmt.Sprintf("%s/%s", r.Owner, r.Name) }
