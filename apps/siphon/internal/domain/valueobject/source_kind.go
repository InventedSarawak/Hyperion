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
	SourceKindMITRE          SourceKind = "mitre"
	SourceKindVendorAdvisory SourceKind = "vendor_advisory"
	SourceKindOSINT          SourceKind = "osint"
	SourceKindPackageFeed    SourceKind = "package_feed"
	SourceKindShodan         SourceKind = "shodan"
	SourceKindGSD            SourceKind = "gsd"
)

// AllSourceKinds lists every source siphon knows about, in the order they are
// documented in docs/INGESTION-SOURCES.md.
func AllSourceKinds() []SourceKind {
	return []SourceKind{
		SourceKindNVD,
		SourceKindGitHubAdvisory,
		SourceKindCISAKEV,
		SourceKindExploitDB,
		SourceKindMITRE,
		SourceKindVendorAdvisory,
		SourceKindOSINT,
		SourceKindPackageFeed,
		SourceKindShodan,
		SourceKindGSD,
	}
}

// IsValid reports whether k is a recognized, usable source kind.
func (k SourceKind) IsValid() bool {
	for _, known := range AllSourceKinds() {
		if k == known {
			return true
		}
	}
	return false
}

// String returns the wire-friendly identifier for the source kind.
func (k SourceKind) String() string { return string(k) }

// DisplayName returns a human-readable label for logs and status output.
func (k SourceKind) DisplayName() string {
	switch k {
	case SourceKindNVD:
		return "National Vulnerability Database (NVD)"
	case SourceKindGitHubAdvisory:
		return "GitHub Advisory Database"
	case SourceKindCISAKEV:
		return "CISA Known Exploited Vulnerabilities (KEV)"
	case SourceKindExploitDB:
		return "Exploit-DB"
	case SourceKindMITRE:
		return "MITRE CVE List"
	case SourceKindVendorAdvisory:
		return "Vendor Security Advisories"
	case SourceKindOSINT:
		return "OSINT & Mailing Lists"
	case SourceKindPackageFeed:
		return "Package Manager Feeds"
	case SourceKindShodan:
		return "Shodan / Censys"
	case SourceKindGSD:
		return "Global Security Database (GSD/OSV)"
	default:
		return "unknown source"
	}
}
