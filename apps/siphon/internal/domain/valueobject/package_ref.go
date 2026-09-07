package valueobject

import (
	"errors"
	"strings"
)

// Ecosystem is the package registry a library is published to. Advisory feeds
// spell these many ways ("pip", "PyPI", "crates.io"); siphon normalizes at the
// domain boundary so downstream services receive one canonical form.
type Ecosystem string

const (
	EcosystemUnknown   Ecosystem = ""
	EcosystemGo        Ecosystem = "go"
	EcosystemNPM       Ecosystem = "npm"
	EcosystemPyPI      Ecosystem = "pypi"
	EcosystemMaven     Ecosystem = "maven"
	EcosystemCargo     Ecosystem = "cargo"
	EcosystemRubyGems  Ecosystem = "rubygems"
	EcosystemNuGet     Ecosystem = "nuget"
	EcosystemPackagist Ecosystem = "packagist"
)

// ParseEcosystem maps an upstream spelling onto the canonical form. An
// unrecognized registry becomes EcosystemUnknown rather than an error: the
// package is still worth reporting by name.
func ParseEcosystem(s string) Ecosystem {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "go", "golang", "gomodules":
		return EcosystemGo
	case "npm", "node", "nodejs":
		return EcosystemNPM
	case "pypi", "pip", "python":
		return EcosystemPyPI
	case "maven", "java":
		return EcosystemMaven
	case "cargo", "crates.io", "crates", "rust":
		return EcosystemCargo
	case "rubygems", "gem", "ruby":
		return EcosystemRubyGems
	case "nuget", "dotnet", ".net":
		return EcosystemNuGet
	case "packagist", "composer", "php":
		return EcosystemPackagist
	default:
		return EcosystemUnknown
	}
}

// String returns the canonical identifier.
func (e Ecosystem) String() string { return string(e) }

// PackageRef names one library an advisory declares vulnerable. Version holds
// the affected range as the feed expressed it, when it gives one.
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
