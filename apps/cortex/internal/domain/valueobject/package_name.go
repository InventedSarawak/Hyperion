package valueobject

import "strings"

// NormalizeName renders a package name in the form its registry considers
// canonical, so that two spellings of one library are one library.
//
// This is a join key, and the two sides spell things differently: a .csproj
// writes `newtonsoft.json` while every advisory writes `Newtonsoft.Json`. NuGet
// ids are case-insensitive, so those are the same package — but a graph keyed
// on the literal text has them as two, and a repository requiring one never
// reaches advisories filed against the other. That is exposure going unreported,
// which is the failure mode that matters most here.
//
// Only registries whose own rules say two spellings are one name are folded.
// RubyGems ids are case-sensitive by specification, so `Rails` and `rails`
// could in principle be different gems, and merging them would be inventing a
// fact rather than applying one.
func NormalizeName(ecosystem Ecosystem, name string) string {
	name = strings.TrimSpace(name)
	switch ecosystem {
	case EcosystemNuGet:
		// Ids are compared case-insensitively.
		return strings.ToLower(name)
	case EcosystemPackagist:
		// vendor/package, compared case-insensitively.
		return strings.ToLower(name)
	case EcosystemPyPI:
		return normalizePyPI(name)
	default:
		return name
	}
}

// normalizePyPI applies PEP 503: lower case, with any run of -, _ or .
// collapsed to a single -. It is how PyPI itself compares names, and how
// advisories store them.
func normalizePyPI(name string) string {
	lowered := strings.ToLower(name)

	var b strings.Builder
	b.Grow(len(lowered))
	separator := false
	for _, r := range lowered {
		if r == '-' || r == '_' || r == '.' {
			separator = true
			continue
		}
		if separator && b.Len() > 0 {
			b.WriteByte('-')
		}
		separator = false
		b.WriteRune(r)
	}
	return b.String()
}
