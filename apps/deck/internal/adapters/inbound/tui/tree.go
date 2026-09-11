package tui

import (
	"fmt"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// Box-drawing pieces for the dependency tree.
const (
	branch     = "├── "
	lastBranch = "└── "
	gap        = "    "
)

// RenderTree draws a blast radius with each exposed repository at the top of
// its own tree, and beneath it the dependency chain that leads down to the
// vulnerable package and the finding:
//
//	vercel/commerce  (2 hops)
//	└── npm:next
//	    └── npm:react-server-dom-webpack
//	        └── CVE-2025-55182
//
// Repository first, because that is the question being asked — "which of my
// repositories does this reach, and how?" — and the answer reads top-down as
// the path the vulnerable code travels to get there. Packages the advisory
// names that no tracked repository reaches are listed last, so an unreached
// package is visible rather than silently missing.
//
// It is a plain string function so the layout can be tested without driving a
// terminal — the part worth getting right is the shape, not the styling.
func RenderTree(radius model.BlastRadius) string {
	var b strings.Builder

	cve := radius.CVEID
	if cve == "" {
		return "(no vulnerability selected)\n"
	}

	// A CVE with no package linkage is unanswerable, not unaffected. Saying
	// "0 repositories" here would be the most dangerous kind of wrong.
	if !radius.Linked() {
		b.WriteString(cve + "\n")
		b.WriteString(lastBranch + "no package linkage for this CVE — blast radius unknown\n")
		return b.String()
	}

	for i, repo := range radius.Repositories {
		if i > 0 {
			b.WriteString("\n")
		}
		b.WriteString(fmt.Sprintf("%s  (%s)%s\n", repo.FullName, repo.Reach(), verdictNote(repo)))

		chain := append(chainBelow(repo), cve)
		for depth, node := range chain {
			b.WriteString(strings.Repeat(gap, depth) + lastBranch + node + "\n")
		}
	}

	if unreached := unreachedPackages(radius); len(unreached) > 0 {
		if len(radius.Repositories) > 0 {
			b.WriteString("\n")
		}
		b.WriteString("not reached by any tracked repository\n")
		for i, pkg := range unreached {
			prefix := branch
			if i == len(unreached)-1 {
				prefix = lastBranch
			}
			b.WriteString(prefix + pkg + "\n")
		}
	}
	return b.String()
}

// verdictNote says whether the version the repository declares is actually
// affected — depending on a library is not the same as being exposed to its
// flaw — with both versions, so the judgement can be checked by eye.
func verdictNote(repo model.ImpactedRepository) string {
	var what string
	switch repo.Verdict {
	case model.VerdictAffected:
		what = "affected"
	case model.VerdictPossiblyAffected:
		what = "possibly affected"
	case model.VerdictNotAffected:
		what = "ruled out by version"
	case model.VerdictUnknown:
		what = "version unknown"
	default:
		return ""
	}
	return fmt.Sprintf("  · %s: declares %s, affected %s", what, orDash(repo.DeclaredVersion), orDash(repo.AffectedVersions))
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}

// chainBelow is the dependency path from a repository down to the vulnerable
// package, without the repository itself. The path cortex reports starts at
// the repository; when it is missing, the package reached is all there is.
func chainBelow(repo model.ImpactedRepository) []string {
	path := repo.Path
	if len(path) > 0 && path[0] == repo.FullName {
		path = path[1:]
	}
	if len(path) == 0 && repo.ViaPackage != "" {
		path = []string{repo.ViaPackage}
	}
	return append([]string(nil), path...)
}

// unreachedPackages lists the vulnerable packages no repository is reached
// through, in the order the advisory named them.
func unreachedPackages(radius model.BlastRadius) []string {
	reached := make(map[string]struct{}, len(radius.Repositories))
	for _, r := range radius.Repositories {
		reached[r.ViaPackage] = struct{}{}
	}
	seen := make(map[string]struct{}, len(radius.VulnerablePackages))
	var out []string
	for _, pkg := range radius.VulnerablePackages {
		if _, ok := reached[pkg]; ok {
			continue
		}
		if _, dup := seen[pkg]; dup {
			continue
		}
		seen[pkg] = struct{}{}
		out = append(out, pkg)
	}
	return out
}
