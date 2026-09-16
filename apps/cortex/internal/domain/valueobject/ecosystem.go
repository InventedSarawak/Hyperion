// Package valueobject holds cortex's domain value objects: small, immutable
// types defined by their value, carrying their own validity and normalization
// rules.
package valueobject

import "strings"

// Ecosystem is the package registry a library is published to. Upstream feeds
// spell these many ways ("pip", "PyPI", "crates.io", "rust"); the domain keeps
// one lowercase canonical form and ParseEcosystem does the normalizing.
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

// AllEcosystems lists every registry cortex recognizes.
func AllEcosystems() []Ecosystem {
	return []Ecosystem{
		EcosystemGo, EcosystemNPM, EcosystemPyPI, EcosystemMaven,
		EcosystemCargo, EcosystemRubyGems, EcosystemNuGet, EcosystemPackagist,
	}
}

// IsValid reports whether e is a recognized registry.
func (e Ecosystem) IsValid() bool {
	for _, known := range AllEcosystems() {
		if e == known {
			return true
		}
	}
	return false
}

// String returns the canonical identifier.
func (e Ecosystem) String() string { return string(e) }

// ParseEcosystem maps an upstream spelling onto the canonical form. Unknown
// values become EcosystemUnknown rather than an error: a library from a
// registry we do not model yet is still worth recording by name.
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
