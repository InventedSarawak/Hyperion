// Package valueobject holds siphon's domain value objects: small, immutable
// types defined by their value with their own validity rules.
package valueobject

// SourceKind identifies which upstream feed a signal originated from.
// It is a value object: a plain string constrained to a known set.
type SourceKind string

const (
	SourceKindUnspecified    SourceKind = ""
	SourceKindNVD            SourceKind = "nvd"
	SourceKindGitHubAdvisory SourceKind = "github_advisory"
	SourceKindCISAKEV        SourceKind = "cisa_kev"
	SourceKindExploitDB      SourceKind = "exploit_db"
)

// IsValid reports whether k is a recognized, usable source kind.
func (k SourceKind) IsValid() bool {
	switch k {
	case SourceKindNVD, SourceKindGitHubAdvisory, SourceKindCISAKEV, SourceKindExploitDB:
		return true
	default:
		return false
	}
}

// String returns the wire-friendly identifier for the source kind.
func (k SourceKind) String() string { return string(k) }
