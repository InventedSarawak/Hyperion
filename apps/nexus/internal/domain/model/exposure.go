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
// to, for flagging it in a list. Computed false means "unknown", not "clean".
type ExposureSummary struct {
	Computed         bool
	CriticalAffected int
	CriticalPossible int
	HighAffected     int
	HighPossible     int
	Total            int
}

// RepositoryFinding is one finding a repository reaches through one library.
type RepositoryFinding struct {
	Vulnerability    Vulnerability
	Package          string // graph key, e.g. "npm:astro"
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
	Scanned  bool // false: the graph has no such repository, so findings are unknown
	Findings []RepositoryFinding
	Summary  ExposureSummary
}
