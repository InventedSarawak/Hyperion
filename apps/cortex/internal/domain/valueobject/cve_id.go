package valueobject

import (
	"regexp"
	"strings"
)

// cvePattern matches a canonical CVE identifier, case-insensitively.
var cvePattern = regexp.MustCompile(`(?i)^cve-\d{4}-\d{4,}$`)

// NormalizeCVEID trims an identifier and, when it is CVE-shaped, uppercases it
// so "cve-2021-44228" and "CVE-2021-44228" resolve to the same record.
//
// Anything else keeps its case on purpose: GitHub's GHSA identifiers
// (GHSA-jfh8-c2jp-5v3q) are case-sensitive, and uppercasing them would turn a
// valid lookup into a miss.
func NormalizeCVEID(s string) string {
	s = strings.TrimSpace(s)
	if cvePattern.MatchString(s) {
		return strings.ToUpper(s)
	}
	return s
}
