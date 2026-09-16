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

// ParseVersion reads a version as the registries write them: semver
// (1.2.3-rc.1), Go (v1.2.3, pseudo-versions), Python (1.0rc1, 2.0.post1,
// 1.0.dev3), Maven (5.3.20.RELEASE, 2.0.0.Beta1, 1.0-SNAPSHOT) and plain dotted
// numbers, tolerating a leading "v" or "=".
func ParseVersion(raw string) (Version, bool) {
	s := strings.TrimSpace(raw)
	s = strings.TrimLeft(s, "=")
	s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "V")
	if i := strings.IndexByte(s, '+'); i >= 0 {
		s = s[:i]
	}
	if i := strings.IndexByte(s, '!'); i >= 0 {
		s = s[i+1:] // a PEP 440 epoch, shared by every release of a package
	}
	m := versionCore.FindStringSubmatch(s)
	if m == nil {
		return Version{}, false
	}
	fields := strings.Split(m[1], ".")
	parts := make([]uint64, 0, len(fields))
	for _, f := range fields {
		n, err := strconv.ParseUint(f, 10, 64)
		if err != nil {
			return Version{}, false
		}
		parts = append(parts, n)
	}
	rest := m[2]
	switch {
	case rest == "":
		return Version{parts: parts}, true
	case rest[0] == '-':
		if len(rest) == 1 {
			return Version{}, false
		}
		return Version{parts: parts, pre: strings.Split(rest[1:], ".")}, true
	}
	return qualified(parts, strings.TrimLeft(rest, "._"))
}

var (
	versionCore = regexp.MustCompile(`^(\d+(?:\.\d+)*)(.*)$`)
	preTag      = regexp.MustCompile(`(?i)^(alpha|a|beta|b|milestone|m|rc|cr|c|preview|pre|dev|snapshot)[.-]?(\d*)`)
	postTag     = regexp.MustCompile(`(?i)^(post|rev|sp|pl)[.-]?(\d*)`)
)

// qualified reads a version whose numbers are followed by a word rather than
// a semver "-": Python's 1.0rc1 and 2.0.post1, Maven's 5.3.20.RELEASE.
func qualified(parts []uint64, q string) (Version, bool) {
	switch strings.ToLower(q) {
	case "final", "ga", "release":
		return Version{parts: parts}, true // Maven's names for a plain release
	}
	if m := postTag.FindStringSubmatch(q); m != nil {
		// A post-release sorts after its release and before the next one:
		// 2.0.post1 is 2.0.0.1.
		n, _ := strconv.ParseUint(firstDigits(m[2]), 10, 64)
		padded := make([]uint64, max(len(parts), 3), max(len(parts), 3)+1)
		copy(padded, parts)
		return Version{parts: append(padded, n)}, true
	}
	if m := preTag.FindStringSubmatch(q); m != nil {
		pre := []string{canonicalPre(m[1])}
		if m[2] != "" {
			pre = append(pre, m[2])
		}
		return Version{parts: parts, pre: pre}, true
	}
	// Any other word is a pre-release by another name, as Maven treats it.
	// A wildcard is not a version at all.
	if q == "" || strings.ContainsAny(q[:1], "xX*") {
		return Version{}, false
	}
	return Version{parts: parts, pre: strings.FieldsFunc(q, func(r rune) bool { return r == '.' || r == '-' || r == '_' })}, true
}

func firstDigits(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

// canonicalPre names pre-release stages so they sort in release order:
// development builds first (numbers sort before words), then alpha, beta,
// milestone and release candidate.
func canonicalPre(tag string) string {
	switch strings.ToLower(tag) {
	case "dev", "snapshot":
		return "0"
	case "a", "alpha":
		return "alpha"
	case "b", "beta":
		return "beta"
	case "m", "milestone":
		return "milestone"
	default:
		return "rc"
	}
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
//
// Every registry writes constraints its own way, and reading one as another
// gives wrong answers: "1.2" is exactly 1.2 to pip but anything below 2.0 to
// Cargo, and "~1.2" means below 1.3 to npm but below 2.0 to Composer.
func ParseDeclared(eco Ecosystem, raw string) (VersionSet, bool) {
	s := strings.TrimSpace(raw)
	switch eco {
	case EcosystemGo:
		v, ok := ParseVersion(s)
		if !ok {
			return VersionSet{}, false
		}
		return exactly(v), true
	case EcosystemPyPI:
		return parsePEP440(s)
	case EcosystemCargo:
		return parseCargo(s)
	case EcosystemRubyGems:
		return parseRubyGems(s)
	case EcosystemMaven, EcosystemNuGet:
		return parseBracketRange(s)
	case EcosystemPackagist:
		return parseComposer(s)
	default:
		return parseNPMRange(s)
	}
}

// --- Python (PEP 440, plus Poetry's ^ and ~) ---

var pep440Op = regexp.MustCompile(`^(===|==|!=|~=|>=|<=|>|<)?(.+)$`)

func parsePEP440(s string) (VersionSet, bool) {
	s = strings.ReplaceAll(s, " ", "")
	if s == "" || s == "*" {
		return anyVersion, true // unpinned: pip installs whatever is newest
	}
	if strings.HasPrefix(s, "^") || strings.HasPrefix(s, "~") && !strings.HasPrefix(s, "~=") {
		c, ok := npmComparator(s) // Poetry borrows npm's caret and tilde
		if !ok {
			return VersionSet{}, false
		}
		return VersionSet{spans: []interval{c}}, true
	}
	span := interval{}
	for _, clause := range strings.Split(s, ",") {
		c, ok := pep440Clause(clause)
		if !ok {
			return VersionSet{}, false
		}
		span = span.intersect(c)
	}
	return VersionSet{spans: []interval{span}}, true
}

func pep440Clause(clause string) (interval, bool) {
	m := pep440Op.FindStringSubmatch(clause)
	if m == nil {
		return interval{}, false
	}
	op, ver := m[1], m[2]
	if op == "!=" {
		return interval{}, true // a hole in the range; ignoring it only widens what is judged
	}
	if strings.HasSuffix(ver, ".*") {
		if op != "==" && op != "" {
			return interval{}, false
		}
		p, ok := parsePartial(strings.TrimSuffix(ver, ".*"))
		if !ok || len(p.parts) == 0 {
			return interval{}, false
		}
		return interval{lo: bound{p.floor(), true, true}, hi: bound{bumpAt(p.parts, len(p.parts)-1), false, true}}, true
	}
	v, ok := ParseVersion(ver)
	if !ok {
		return interval{}, false
	}
	switch op {
	case "~=":
		// Compatible release: ~=1.4.2 is >=1.4.2 and ==1.4.*.
		if len(v.parts) < 2 {
			return interval{}, false
		}
		return interval{lo: bound{v, true, true}, hi: bound{bumpAt(v.parts, len(v.parts)-2), false, true}}, true
	case "", "==", "===":
		return interval{lo: bound{v, true, true}, hi: bound{v, true, true}}, true
	default:
		return constraint(op, v), true
	}
}

// --- Cargo ---

// parseCargo reads Cargo's requirements, where a bare "1.2" is a caret
// requirement: anything compatible with 1.2, i.e. below 2.0.
func parseCargo(s string) (VersionSet, bool) {
	if s == "" || s == "*" {
		return anyVersion, true
	}
	span := interval{}
	for _, clause := range strings.Split(s, ",") {
		token := strings.ReplaceAll(strings.TrimSpace(clause), " ", "")
		if token != "" && token[0] >= '0' && token[0] <= '9' && !strings.ContainsAny(token, "*xX") {
			token = "^" + token
		}
		c, ok := npmComparator(token)
		if !ok {
			return VersionSet{}, false
		}
		span = span.intersect(c)
	}
	return VersionSet{spans: []interval{span}}, true
}

// --- RubyGems ---

var rubyOp = regexp.MustCompile(`^(>=|<=|!=|~>|=|>|<)?(.+)$`)

// parseRubyGems reads Gem requirements: "~> 7.0" (pessimistic), ">= 1.2",
// "= 1.2.3", and a bare version, which is exact — as a Gemfile.lock records.
func parseRubyGems(s string) (VersionSet, bool) {
	if s == "" {
		return anyVersion, true
	}
	span := interval{}
	for _, clause := range strings.Split(s, ",") {
		m := rubyOp.FindStringSubmatch(strings.ReplaceAll(strings.TrimSpace(clause), " ", ""))
		if m == nil {
			return VersionSet{}, false
		}
		if m[1] == "!=" {
			continue
		}
		v, ok := ParseVersion(m[2])
		if !ok {
			return VersionSet{}, false
		}
		switch m[1] {
		case "~>":
			span = span.intersect(pessimistic(v))
		case "", "=":
			span = span.intersect(interval{lo: bound{v, true, true}, hi: bound{v, true, true}})
		default:
			span = span.intersect(constraint(m[1], v))
		}
	}
	return VersionSet{spans: []interval{span}}, true
}

// pessimistic is RubyGems' ~> and Composer's ~: the last component given may
// rise, the one before it may not. ~> 2.2 allows 2.x from 2.2; ~> 2.2.0 allows
// 2.2.x.
func pessimistic(v Version) interval {
	i := max(0, len(v.parts)-2)
	return interval{lo: bound{v, true, true}, hi: bound{bumpAt(v.parts, i), false, true}}
}

// --- Maven and NuGet ---

var bracketRange = regexp.MustCompile(`[\[(][^\])]*[\])]`)

// parseBracketRange reads Maven and NuGet versions: a bare version, which is
// what gets built (Maven treats it as a soft pin that resolution rarely moves,
// NuGet resolves to the lowest version allowed), or interval notation such as
// "[1.0,2.0)", "[1.2]" and "(,1.0],[1.2,)". No version at all — a property
// this scan could not resolve — is unknown, not "anything".
func parseBracketRange(s string) (VersionSet, bool) {
	if s == "" {
		return VersionSet{}, false
	}
	if s[0] != '[' && s[0] != '(' {
		v, ok := ParseVersion(s)
		if !ok {
			return VersionSet{}, false
		}
		return exactly(v), true
	}
	var set VersionSet
	for _, r := range bracketRange.FindAllString(s, -1) {
		inner := r[1 : len(r)-1]
		loInclusive, hiInclusive := r[0] == '[', r[len(r)-1] == ']'
		lo, hi, isRange := strings.Cut(inner, ",")
		if !isRange {
			v, ok := ParseVersion(inner)
			if !ok {
				return VersionSet{}, false
			}
			set.spans = append(set.spans, interval{lo: bound{v, true, true}, hi: bound{v, true, true}})
			continue
		}
		span := interval{}
		if lo = strings.TrimSpace(lo); lo != "" {
			v, ok := ParseVersion(lo)
			if !ok {
				return VersionSet{}, false
			}
			span.lo = bound{v, loInclusive, true}
		}
		if hi = strings.TrimSpace(hi); hi != "" {
			v, ok := ParseVersion(hi)
			if !ok {
				return VersionSet{}, false
			}
			span.hi = bound{v, hiInclusive, true}
		}
		set.spans = append(set.spans, span)
	}
	if len(set.spans) == 0 {
		return VersionSet{}, false
	}
	return set, true
}

// --- Composer ---

var stabilityFlag = regexp.MustCompile(`@(?i:dev|alpha|beta|rc|stable)`)

// parseComposer reads Composer constraints. They look like npm's but tilde
// differs: "~1.2" allows anything below 2.0. A branch ("dev-main") is not a
// version.
func parseComposer(s string) (VersionSet, bool) {
	s = strings.TrimSpace(stabilityFlag.ReplaceAllString(s, ""))
	if s == "" || s == "*" {
		return anyVersion, true
	}
	if strings.HasPrefix(s, "dev-") {
		return VersionSet{}, false
	}
	var set VersionSet
	for _, alt := range strings.Split(strings.ReplaceAll(s, "||", "|"), "|") {
		alt = strings.TrimSpace(alt)
		if strings.Contains(alt, " - ") {
			sub, ok := parseNPMRange(alt)
			if !ok {
				return VersionSet{}, false
			}
			set.spans = append(set.spans, sub.spans...)
			continue
		}
		span := interval{}
		for _, token := range strings.FieldsFunc(alt, func(r rune) bool { return r == ' ' || r == ',' }) {
			if strings.HasPrefix(token, "~") {
				v, ok := ParseVersion(token[1:])
				if !ok {
					return VersionSet{}, false
				}
				span = span.intersect(pessimistic(v))
				continue
			}
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
	out := make([]uint64, max(3, i+1))
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
