package model

import (
	"errors"
	"strings"
)

// Author is whoever owns a repository — a person or an organization. It is
// modelled as its own entity so the graph can answer the second-order
// question: once one of a maintainer's projects is hit, what else of theirs
// sits on the same vulnerable library?
type Author struct {
	Login string // handle, unique within the forge, e.g. "kubernetes"
	Name  string // display name, when the forge exposes one
	URL   string // profile URL
}

// ErrMissingAuthorLogin is returned when an author has no handle.
var ErrMissingAuthorLogin = errors.New("author: login is required")

// Validate enforces the entity's invariants.
func (a Author) Validate() error {
	if strings.TrimSpace(a.Login) == "" {
		return ErrMissingAuthorLogin
	}
	return nil
}

// IsZero reports whether the author is absent. Authorship is optional: a
// manifest can be recorded without knowing who owns the repository.
func (a Author) IsZero() bool { return strings.TrimSpace(a.Login) == "" }
