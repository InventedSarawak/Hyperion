package valueobject

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Version is a release number as package registries write it: numeric
// components (1.2.3, 2.4, 1.175.0), an optional pre-release tag (-canary.60,
// -dev.0) and optional build metadata, which carries no order and is dropped.
// Missing components are zeros, so "2.4" and "2.4.0" are the same release.
type Version struct {
	parts []uint64
	pre   []string // pre-release identifiers; nil for a release
}

// ParseVersion reads a version, tolerating a leading "v" (Go) or "=".
func ParseVersion(raw string) (Version, bool) {
	s := strings.TrimSpace(raw)
	s = strings.TrimLeft(s, "=")
	s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "V")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var pre []string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		if i+1 >= len(s) {
			return Version{}, false
		}
		pre = strings.Split(s[i+1:], ".")
		s = s[:i]
	}
	if s == "" {
		return Version{}, false
	}
	fields := strings.Split(s, ".")
	parts := make([]uint64, 0, len(fields))
	for _, f := range fields {
		n, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return Version{}, false
		}
		parts = append(parts, n)
	}
	return Version{parts: parts, pre: pre}, true
}

// Compare orders two versions: -1, 0 or 1. A pre-release sorts before its
// release, and pre-release identifiers compare as semver says: numbers
// numerically, below words, which compare lexically.
func (v Version) Compare(o Version) int {
	for i := range max(len(v.parts), len(o.parts)) {
		a, b := at(v.parts, i), at(o.parts, i)
		if a != b {
			if a < b {
				return -1
			}
			return 1
		}
	}
	switch {
	case v.pre == nil && o.pre == nil:
		return 0
	case v.pre == nil:
		return 1
	case o.pre == nil:
		return -1
	}
	for i := range min(len(v.pre), len(o.pre)) {
		if c := comparePre(v.pre[i], o.pre[i]); c != 0 {
			return c
		}
	}
	switch {
	case len(v.pre) < len(o.pre):
		return -1
	case len(v.pre) > len(o.pre):
		return 1
	}
	return 0
}

func at(parts []uint64, i int) uint64 {
	if i < len(parts) {
		return parts[i]
	}
	return 0
}

func comparePre(a, b string) int {
	an, aErr := strconv.ParseUint(a, 10, 64)
	bn, bErr := strconv.ParseUint(b, 10, 64)
	switch {
	case aErr == nil && bErr == nil:
		switch {
		case an < bn:
			return -1
		case an > bn:
			return 1
		}
		return 0
	case aErr == nil:
		return -1
	case bErr == nil:
		return 1
	}
	return strings.Compare(a, b)
}

// String renders the version in its canonical form.
func (v Version) String() string {
	var b strings.Builder
	for i, p := range v.parts {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.FormatUint(p, 10))
	}
	if v.pre != nil {
		b.WriteByte('-')
		b.WriteString(strings.Join(v.pre, "."))
	}
	return b.String()
}

// --- sets of versions ---

// bound is one end of an interval; an unset bound is unbounded.
type bound struct {
	v         Version
	inclusive bool
	set       bool
}

// interval is a contiguous run of versions.
type interval struct{ lo, hi bound }

// VersionSet is a union of intervals: every version a declaration allows, or
// every version an advisory says is affected.
type VersionSet struct{ spans []interval }

// anyVersion is the set of every version.
var anyVersion = VersionSet{spans: []interval{{}}}

func (i interval) empty() bool {
	if !i.lo.set || !i.hi.set {
		return false
	}
	c := i.lo.v.Compare(i.hi.v)
	return c > 0 || c == 0 && !(i.lo.inclusive && i.hi.inclusive)
}

// lowerBelow reports whether lower bound a admits versions b does not.
func lowerBelow(a, b bound) bool {
	switch {
	case !a.set:
		return b.set
	case !b.set:
		return false
	}
	if c := a.v.Compare(b.v); c != 0 {
		return c < 0
	}
	return a.inclusive && !b.inclusive
}

// upperAbove reports whether upper bound a admits versions b does not.
func upperAbove(a, b bound) bool {
	switch {
	case !a.set:
		return b.set
	case !b.set:
		return false
	}
	if c := a.v.Compare(b.v); c != 0 {
		return c > 0
	}
	return a.inclusive && !b.inclusive
}

func (i interval) intersect(o interval) interval {
	out := i
	if lowerBelow(out.lo, o.lo) {
		out.lo = o.lo
	}
	if upperAbove(out.hi, o.hi) {
		out.hi = o.hi
	}
	return out
}

// contains reports whether every version in inner is in i.
func (i interval) contains(inner interval) bool {
	return !lowerBelow(inner.lo, i.lo) && !upperAbove(inner.hi, i.hi)
}

// touches reports whether a (ending first) and b overlap or meet with no
// version between them, so their union is one interval.
func touches(a, b interval) bool {
	if !a.hi.set || !b.lo.set {
		return true
	}
	c := a.hi.v.Compare(b.lo.v)
	return c > 0 || c == 0 && (a.hi.inclusive || b.lo.inclusive)
}

// merged returns the set as sorted, disjoint intervals.
func (s VersionSet) merged() []interval {
	spans := make([]interval, 0, len(s.spans))
	for _, sp := range s.spans {
		if !sp.empty() {
			spans = append(spans, sp)
		}
	}
	slices.SortFunc(spans, func(a, b interval) int {
		switch {
		case lowerBelow(a.lo, b.lo):
			return -1
		case lowerBelow(b.lo, a.lo):
			return 1
		}
		return 0
	})
	var out []interval
	for _, sp := range spans {
		if n := len(out); n > 0 && touches(out[n-1], sp) {
			if upperAbove(sp.hi, out[n-1].hi) {
				out[n-1].hi = sp.hi
			}
			continue
		}
		out = append(out, sp)
	}
	return out
}

// Intersects reports whether any version is in both sets.
func (s VersionSet) Intersects(o VersionSet) bool {
	for _, a := range s.spans {
		for _, b := range o.spans {
			if !a.empty() && !b.empty() && !a.intersect(b).empty() {
				return true
			}
		}
	}
	return false
}

// Within reports whether every version in s is also in o.
func (s VersionSet) Within(o VersionSet) bool {
	cover := o.merged()
	for _, sp := range s.merged() {
		if !slices.ContainsFunc(cover, func(c interval) bool { return c.contains(sp) }) {
			return false
		}
	}
	return true
}

// --- advisory ranges ---

var comparator = regexp.MustCompile(`^(>=|<=|>|<|==|=)?\s*(\S+)$`)

// ParseAffectedRange reads the versions an advisory says are affected, in the
// form every feed adapter writes them: comparators joined by "," (and) and
// "||" (or) — ">= 5.2.0, < 5.12.8", "= 0.30.4 || = 1.14.1", ">= 0".
func ParseAffectedRange(raw string) (VersionSet, bool) {
	if strings.TrimSpace(raw) == "" {
		return VersionSet{}, false
	}
	var set VersionSet
	for _, alt := range strings.Split(raw, "||") {
		span := interval{}
		for _, part := range strings.Split(alt, ",") {
			m := comparator.FindStringSubmatch(strings.TrimSpace(part))
			if m == nil {
				return VersionSet{}, false
			}
			v, ok := ParseVersion(m[2])
			if !ok {
				return VersionSet{}, false
			}
			span = span.intersect(constraint(m[1], v))
		}
		set.spans = append(set.spans, span)
	}
	return set, true
}

// constraint is the interval one comparator admits.
func constraint(op string, v Version) interval {
	switch op {
	case ">=":
		return interval{lo: bound{v, true, true}}
	case ">":
		return interval{lo: bound{v, false, true}}
	case "<=":
		return interval{hi: bound{v, true, true}}
	case "<":
		return interval{hi: bound{v, false, true}}
	default:
		return interval{lo: bound{v, true, true}, hi: bound{v, true, true}}
	}
}

// --- declared versions ---

// ParseDeclared reads the versions a manifest allows for a dependency.
//
// A go.mod requirement names the one version the build selects. npm's
// package.json usually names a range — "^5.11.0" allows everything up to
// 6.0.0 — so it is read as the set of versions npm could install. Dist-tags
// ("latest"), git and file references name no version, and report false.
func ParseDeclared(eco Ecosystem, raw string) (VersionSet, bool) {
	s := strings.TrimSpace(raw)
	if eco == EcosystemGo {
		v, ok := ParseVersion(s)
		if !ok {
			return VersionSet{}, false
		}
		return exactly(v), true
	}
	return parseNPMRange(s)
}

func exactly(v Version) VersionSet {
	return VersionSet{spans: []interval{{lo: bound{v, true, true}, hi: bound{v, true, true}}}}
}

// parseNPMRange implements npm's range grammar: "||" alternatives, hyphen
// ranges, and space-separated comparators with ^, ~, x-ranges and partials.
func parseNPMRange(s string) (VersionSet, bool) {
	if strings.HasPrefix(s, "npm:") { // an alias: "npm:other-name@^1.2.0"
		at := strings.LastIndexByte(s, '@')
		if at < 0 {
			return VersionSet{}, false
		}
		s = s[at+1:]
	}
	if s == "" || s == "*" || s == "x" || s == "X" {
		return anyVersion, true
	}
	var set VersionSet
	for _, alt := range strings.Split(s, "||") {
		alt = strings.TrimSpace(alt)
		if alt == "" || alt == "*" {
			set.spans = append(set.spans, interval{})
			continue
		}
		if lo, hi, ok := strings.Cut(alt, " - "); ok {
			from, okFrom := parsePartial(lo)
			to, okTo := parsePartial(hi)
			if !okFrom || !okTo {
				return VersionSet{}, false
			}
			span := interval{lo: bound{from.floor(), true, true}}
			if to.wild {
				span.hi = bound{to.ceiling(), false, true}
			} else {
				span.hi = bound{to.floor(), true, true}
			}
			set.spans = append(set.spans, span)
			continue
		}
		span := interval{}
		for _, token := range strings.Fields(alt) {
			c, ok := npmComparator(token)
			if !ok {
				return VersionSet{}, false
			}
			span = span.intersect(c)
		}
		set.spans = append(set.spans, span)
	}
	return set, true
}

// partial is a version that may stop early or end in a wildcard: "1", "1.2",
// "1.2.x". wild is set when a component was left open.
type partial struct {
	parts []uint64
	pre   []string
	wild  bool
}

func parsePartial(raw string) (partial, bool) {
	s := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(raw), "v"), "=")
	if s == "" {
		return partial{}, false
	}
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	var pre []string
	if i := strings.IndexByte(s, '-'); i >= 0 {
		pre = strings.Split(s[i+1:], ".")
		s = s[:i]
	}
	var p partial
	for _, f := range strings.Split(s, ".") {
		if f == "x" || f == "X" || f == "*" {
			p.wild = true
			break
		}
		n, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return partial{}, false
		}
		p.parts = append(p.parts, n)
	}
	if len(p.parts) < 3 {
		p.wild = true
	}
	if len(p.parts) > 3 {
		return partial{}, false
	}
	p.pre = pre
	return p, true
}

// floor is the lowest version the partial matches.
func (p partial) floor() Version {
	parts := append([]uint64{}, p.parts...)
	for len(parts) < 3 {
		parts = append(parts, 0)
	}
	return Version{parts: parts, pre: p.pre}
}

// ceiling is the lowest version above everything the partial matches: "1.2"
// matches up to 1.3.0, excluding its pre-releases — hence the "-0".
func (p partial) ceiling() Version {
	return bumpAt(p.parts, len(p.parts)-1)
}

// bumpAt increments component i, zeroes the rest, and returns the lowest
// pre-release of the result, so the bound excludes that line entirely.
func bumpAt(parts []uint64, i int) Version {
	if i < 0 {
		return Version{parts: []uint64{^uint64(0)}}
	}
	out := make([]uint64, 3)
	copy(out, parts[:i])
	out[i] = parts[i] + 1
	return Version{parts: out, pre: []string{"0"}}
}

// npmComparator reads one comparator token: "^1.2.3", "~1.2", ">=1.0.0",
// "<2", "1.x", "=1.2.3".
func npmComparator(token string) (interval, bool) {
	op := ""
	for _, prefix := range []string{">=", "<=", "~>", ">", "<", "=", "^", "~"} {
		if strings.HasPrefix(token, prefix) {
			op, token = prefix, token[len(prefix):]
			break
		}
	}
	p, ok := parsePartial(token)
	if !ok {
		return interval{}, false
	}
	floor := bound{p.floor(), true, true}
	switch op {
	case "^":
		// Up to the next change in the leftmost non-zero component.
		i := 0
		for i < len(p.parts)-1 && p.parts[i] == 0 {
			i++
		}
		if len(p.parts) == 0 {
			return interval{}, true
		}
		return interval{lo: floor, hi: bound{bumpAt(p.floor().parts, i), false, true}}, true
	case "~", "~>":
		i := min(1, len(p.parts)-1)
		if len(p.parts) == 0 {
			return interval{}, true
		}
		return interval{lo: floor, hi: bound{bumpAt(p.floor().parts, i), false, true}}, true
	case ">=":
		return interval{lo: floor}, true
	case ">":
		if p.wild && len(p.parts) > 0 {
			return interval{lo: bound{p.ceiling(), true, true}}, true
		}
		return interval{lo: bound{p.floor(), false, true}}, true
	case "<":
		return interval{hi: bound{p.floor().withLowestPre(), false, true}}, true
	case "<=":
		if p.wild && len(p.parts) > 0 {
			return interval{hi: bound{p.ceiling(), false, true}}, true
		}
		return interval{hi: bound{p.floor(), true, true}}, true
	default: // "=" or bare
		if len(p.parts) == 0 {
			return interval{}, true
		}
		if p.wild {
			return interval{lo: floor, hi: bound{p.ceiling(), false, true}}, true
		}
		return interval{lo: floor, hi: floor}, true
	}
}

// withLowestPre makes "<1.2.3" exclude 1.2.3's pre-releases too, as npm does.
func (v Version) withLowestPre() Version {
	if v.pre != nil {
		return v
	}
	return Version{parts: v.parts, pre: []string{"0"}}
}

// --- judging exposure ---

// ExposureVerdict says whether a dependency declaration lets in a vulnerable
// version.
type ExposureVerdict string

const (
	// ExposureAffected: every version the declaration allows is affected.
	ExposureAffected ExposureVerdict = "affected"
	// ExposurePossible: some allowed versions are affected; the installed
	// one — which only a lockfile records — decides.
	ExposurePossible ExposureVerdict = "possibly_affected"
	// ExposureNotAffected: no allowed version is affected.
	ExposureNotAffected ExposureVerdict = "not_affected"
	// ExposureUnknown: one side could not be read.
	ExposureUnknown ExposureVerdict = "unknown"
)

// verdictRank orders verdicts from harmless to certain.
var verdictRank = map[ExposureVerdict]int{
	ExposureNotAffected: 0,
	ExposureUnknown:     1,
	ExposurePossible:    2,
	ExposureAffected:    3,
}

// Worse reports whether v is a stronger claim of exposure than o.
func (v ExposureVerdict) Worse(o ExposureVerdict) bool { return verdictRank[v] > verdictRank[o] }

// Exposed reports whether the verdict leaves the repository possibly exposed.
// Unknown counts: a finding that cannot be ruled out is not cleared.
func (v ExposureVerdict) Exposed() bool { return v != ExposureNotAffected }

// JudgeExposure compares what a manifest declares with what an advisory says
// is affected.
func JudgeExposure(eco Ecosystem, declared, affected string) ExposureVerdict {
	vulnerable, ok := ParseAffectedRange(affected)
	if !ok {
		return ExposureUnknown
	}
	allowed, ok := ParseDeclared(eco, declared)
	if !ok {
		return ExposureUnknown
	}
	switch {
	case !allowed.Intersects(vulnerable):
		return ExposureNotAffected
	case allowed.Within(vulnerable):
		return ExposureAffected
	default:
		return ExposurePossible
	}
}
