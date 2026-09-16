package valueobject

import (
	"regexp"
	"strings"
)

// Scheme is the numbering authority behind an identifier.
//
// A finding usually has several: NVD knows it as a CVE, GitHub as a GHSA,
// OSV's malicious-packages project as a MAL, the Python advisory database as a
// PYSEC. They are all the same finding, and the domain treats them that way —
// which id each feed happened to send must not decide whether two reports
// merge or split.
type Scheme string

const (
	SchemeCVE   Scheme = "CVE"   // CVE programme: flaws in legitimate software
	SchemeGHSA  Scheme = "GHSA"  // GitHub Security Advisories: every GitHub advisory
	SchemeMAL   Scheme = "MAL"   // OpenSSF malicious packages
	SchemeOther Scheme = "OTHER" // PYSEC-, GO-, RUSTSEC-, OSV-, GSD-, …
)

// rank orders schemes for choosing a canonical id. CVE first because it is
// what the most feeds report under, so it is what lets reports reconcile;
// then GHSA, which GitHub assigns to every advisory it holds; then MAL, which
// is the only id most malware ever gets.
var rank = map[Scheme]int{SchemeCVE: 0, SchemeGHSA: 1, SchemeMAL: 2, SchemeOther: 3}

// Identifier is one id a finding is known by, in canonical form.
type Identifier struct {
	Scheme Scheme
	Value  string
}

var (
	cvePattern   = regexp.MustCompile(`(?i)^cve-\d{4}-\d{4,}$`)
	ghsaPattern  = regexp.MustCompile(`(?i)^ghsa(-[23456789cfghjmpqrvwx]{4}){3}$`)
	malPattern   = regexp.MustCompile(`(?i)^mal-\d{4}-\d+$`)
	otherPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*-[A-Za-z0-9][A-Za-z0-9._:-]*$`)
)

// ParseIdentifier recognises an id and puts it in canonical form, so that
// "cve-2021-44228" and "CVE-2021-44228", or "ghsa-JFH8-…" and "GHSA-jfh8-…",
// resolve to the same finding:
//
//	CVE   upper-case throughout             CVE-2021-44228
//	GHSA  upper-case prefix, lower-case body GHSA-jfh8-c2jp-5v3q
//	MAL   upper-case                        MAL-2026-2307
//	other upper-case prefix, body as given  PYSEC-2021-19
//
// It reports false for anything that is not an id at all.
func ParseIdentifier(raw string) (Identifier, bool) {
	s := strings.TrimSpace(raw)
	switch {
	case s == "":
		return Identifier{}, false
	case cvePattern.MatchString(s):
		return Identifier{SchemeCVE, strings.ToUpper(s)}, true
	case ghsaPattern.MatchString(s):
		return Identifier{SchemeGHSA, "GHSA" + strings.ToLower(s[4:])}, true
	case malPattern.MatchString(s):
		return Identifier{SchemeMAL, strings.ToUpper(s)}, true
	case otherPattern.MatchString(s):
		prefix, rest, _ := strings.Cut(s, "-")
		// Every database numbers its ids; "log4j-core" and "react-dom" are
		// package names, not advisories.
		if !strings.ContainsAny(rest, "0123456789") {
			return Identifier{}, false
		}
		return Identifier{SchemeOther, strings.ToUpper(prefix) + "-" + rest}, true
	default:
		return Identifier{}, false
	}
}

// NormalizeID returns the canonical form of an id, or the trimmed input when
// it is not a recognisable id (so a lookup of nonsense misses cleanly rather
// than erroring).
func NormalizeID(raw string) string {
	if id, ok := ParseIdentifier(raw); ok {
		return id.Value
	}
	return strings.TrimSpace(raw)
}

// String returns the id in canonical form.
func (i Identifier) String() string { return i.Value }

// outranks reports whether i should be preferred to other as canonical.
func (i Identifier) outranks(other Identifier) bool {
	if rank[i.Scheme] != rank[other.Scheme] {
		return rank[i.Scheme] < rank[other.Scheme]
	}
	return i.Value < other.Value // deterministic within a scheme
}

// Canonical picks, from every id a finding is known by, the one it is stored
// under, and returns the rest as aliases in a stable order. Unrecognisable
// and duplicate ids are dropped.
func Canonical(ids ...string) (string, []string) {
	seen := make(map[string]struct{}, len(ids))
	parsed := make([]Identifier, 0, len(ids))
	for _, raw := range ids {
		id, ok := ParseIdentifier(raw)
		if !ok {
			continue
		}
		if _, dup := seen[id.Value]; dup {
			continue
		}
		seen[id.Value] = struct{}{}
		parsed = append(parsed, id)
	}
	if len(parsed) == 0 {
		return "", nil
	}

	best := 0
	for i := range parsed {
		if parsed[i].outranks(parsed[best]) {
			best = i
		}
	}
	aliases := make([]string, 0, len(parsed)-1)
	for i, id := range parsed {
		if i != best {
			aliases = append(aliases, id.Value)
		}
	}
	SortIDs(aliases)
	return parsed[best].Value, aliases
}

// SortIDs orders ids by scheme rank, then value, in place.
func SortIDs(ids []string) {
	for i := 1; i < len(ids); i++ {
		for j := i; j > 0; j-- {
			a, _ := ParseIdentifier(ids[j-1])
			b, _ := ParseIdentifier(ids[j])
			if !b.outranks(a) {
				break
			}
			ids[j-1], ids[j] = ids[j], ids[j-1]
		}
	}
}

// SchemeOf reports which scheme an id belongs to, or "" for a non-id.
func SchemeOf(raw string) Scheme {
	id, _ := ParseIdentifier(raw)
	return id.Scheme
}
