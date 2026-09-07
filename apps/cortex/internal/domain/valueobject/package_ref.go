package valueobject

import (
	"errors"
	"fmt"
	"strings"
)

// PackageRef names one library, optionally at one version. It is the join key
// between the supply chain (what a repository requires) and the threat feed
// (what an advisory declares vulnerable).
//
// Identity deliberately excludes Version: "lodash" is one library whichever
// version a given repository pins. The pinned version belongs on the
// dependency edge, not on the library itself.
type PackageRef struct {
	Ecosystem Ecosystem
	Name      string
	Version   string
}

// ErrMissingPackageName is returned when a reference has no library name.
var ErrMissingPackageName = errors.New("package ref: name is required")

// NewPackageRef builds a reference, normalizing the ecosystem spelling.
func NewPackageRef(ecosystem, name, version string) PackageRef {
	return PackageRef{
		Ecosystem: ParseEcosystem(ecosystem),
		Name:      strings.TrimSpace(name),
		Version:   strings.TrimSpace(version),
	}
}

// Validate enforces the value object's invariants.
func (p PackageRef) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return ErrMissingPackageName
	}
	return nil
}

// IsZero reports whether the reference names nothing.
func (p PackageRef) IsZero() bool { return p.Name == "" && p.Ecosystem == EcosystemUnknown }

// Key is the version-independent identity, e.g. "npm:lodash". Two references
// with the same key point at the same library node in the graph.
func (p PackageRef) Key() string {
	return fmt.Sprintf("%s:%s", p.Ecosystem, p.Name)
}

// String renders the reference for logs and display, version included.
func (p PackageRef) String() string {
	if p.Version == "" {
		return p.Key()
	}
	return fmt.Sprintf("%s@%s", p.Key(), p.Version)
}
