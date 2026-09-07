// Package cveid extracts CVE identifiers from free text. Several sources
// (Exploit-DB codes, RSS items, advisory bodies) reference CVEs inline rather
// than in a dedicated field.
package cveid

import (
	"regexp"
	"strings"
)

// pattern matches the canonical CVE identifier format.
var pattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,7}`)

// First returns the first CVE id found in s, upper-cased, or "".
func First(s string) string {
	if m := pattern.FindString(s); m != "" {
		return strings.ToUpper(m)
	}
	return ""
}

// All returns every distinct CVE id found in s, upper-cased, in order.
func All(s string) []string {
	matches := pattern.FindAllString(s, -1)
	seen := make(map[string]struct{}, len(matches))

	out := make([]string, 0, len(matches))
	for _, m := range matches {
		id := strings.ToUpper(m)
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	return out
}

// urlPattern matches http(s) URLs embedded in free text.
var urlPattern = regexp.MustCompile(`https?://[^\s;,)"'<>]+`)

// URLs returns every distinct URL found in s, in order.
func URLs(s string) []string {
	matches := urlPattern.FindAllString(s, -1)
	seen := make(map[string]struct{}, len(matches))

	out := make([]string, 0, len(matches))
	for _, m := range matches {
		u := strings.TrimRight(m, ".")
		if _, dup := seen[u]; dup {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	return out
}
