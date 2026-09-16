package model

// Exposure verdicts: whether the version a repository declares lets in a
// version the advisory says is affected.
const (
	VerdictAffected         = "affected"          // every allowed version is affected
	VerdictPossiblyAffected = "possibly_affected" // some are; the installed one decides
	VerdictNotAffected      = "not_affected"      // none are
	VerdictUnknown          = "unknown"           // one side could not be read
)

// ExposureSummary counts the serious findings a repository may be exposed
// to. Computed false means nothing could be judged — unknown, not clean.
type ExposureSummary struct {
	Computed         bool
	CriticalAffected int
	CriticalPossible int
	HighAffected     int
	HighPossible     int
	Total            int
}

// Critical is every critical finding it may be exposed to.
func (s ExposureSummary) Critical() int { return s.CriticalAffected + s.CriticalPossible }

// High is every high-rated finding it may be exposed to.
func (s ExposureSummary) High() int { return s.HighAffected + s.HighPossible }

// RepositoryFinding is one finding a repository reaches through one library.
type RepositoryFinding struct {
	Vulnerability    Vulnerability
	Package          string // e.g. "npm:astro"
	DeclaredVersion  string // what the manifest asks for, e.g. "^5.11.0"
	AffectedVersions string // what the advisory says is affected
	Verdict          string
	Depth            int
	Direct           bool
	Path             []string
}

// RepositoryExposure is which vulnerabilities a repository has.
type RepositoryExposure struct {
	FullName string
	Scanned  bool // false: not in the graph, so its findings are unknown
	Findings []RepositoryFinding
	Summary  ExposureSummary
}
