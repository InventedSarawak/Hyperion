package tui

import (
	"fmt"
	"sort"
	"strings"

	"github.com/inventedsarawak/hyperion/apps/deck/internal/domain/model"
)

// Box-drawing pieces for the dependency tree.
const (
	branch     = "├── "
	lastBranch = "└── "
	trunk      = "│   "
	gap        = "    "
)

// RenderTree draws a blast radius as an ASCII tree: the vulnerability at the
// root, each vulnerable library beneath it, and every exposed repository under
// the library it was reached through.
//
// It is a plain string function so the layout can be tested without driving a
// terminal — the part worth getting right is the shape, not the styling.
func RenderTree(radius model.BlastRadius) string {
	var b strings.Builder

	cve := radius.CVEID
	if cve == "" {
		cve = "(no vulnerability selected)"
	}
	b.WriteString(cve + "\n")

	// A CVE with no package linkage is unanswerable, not unaffected. Saying
	// "0 repositories" here would be the most dangerous kind of wrong.
	if !radius.Linked() {
		b.WriteString(lastBranch + "no package linkage for this CVE — blast radius unknown\n")
		return b.String()
	}

	grouped := radius.ByPackage()
	packages := orderedPackages(radius, grouped)

	for i, pkg := range packages {
		lastPkg := i == len(packages)-1
		b.WriteString(prefix(lastPkg) + pkg + "\n")

		repos := grouped[pkg]
		if len(repos) == 0 {
			b.WriteString(indent(lastPkg) + lastBranch + "no tracked repository depends on this\n")
			continue
		}

		for j, repo := range repos {
			lastRepo := j == len(repos)-1
			b.WriteString(indent(lastPkg) + prefix(lastRepo) +
				fmt.Sprintf("%s  (%s)\n", repo.FullName, repo.Reach()))

			// Only a multi-hop path tells the reader anything the line above
			// did not already say.
			if len(repo.Path) > 2 {
				b.WriteString(indent(lastPkg) + indent(lastRepo) + lastBranch + repo.Chain() + "\n")
			}
		}
	}
	return b.String()
}

// orderedPackages lists the vulnerable packages, those with exposed
// repositories first, then any the advisory named that nothing depends on.
func orderedPackages(radius model.BlastRadius, grouped map[string][]model.ImpactedRepository) []string {
	seen := make(map[string]struct{}, len(radius.VulnerablePackages))
	withRepos := make([]string, 0, len(grouped))
	without := make([]string, 0, len(radius.VulnerablePackages))

	for _, pkg := range radius.VulnerablePackages {
		if _, ok := seen[pkg]; ok {
			continue
		}
		seen[pkg] = struct{}{}
		if len(grouped[pkg]) > 0 {
			withRepos = append(withRepos, pkg)
		} else {
			without = append(without, pkg)
		}
	}

	// A repository can be reached through a library the advisory did not list
	// by that exact name; surface it rather than dropping the finding.
	extra := make([]string, 0)
	for pkg := range grouped {
		if _, ok := seen[pkg]; !ok {
			extra = append(extra, pkg)
		}
	}
	sort.Strings(extra)

	return append(append(withRepos, extra...), without...)
}

func prefix(last bool) string {
	if last {
		return lastBranch
	}
	return branch
}

func indent(last bool) string {
	if last {
		return gap
	}
	return trunk
}
