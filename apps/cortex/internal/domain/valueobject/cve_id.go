package valueobject

// NormalizeCVEID puts any finding id in canonical form. It predates support
// for GHSA and MAL ids and keeps its name for its callers; the rule itself is
// ParseIdentifier's.
func NormalizeCVEID(s string) string { return NormalizeID(s) }
