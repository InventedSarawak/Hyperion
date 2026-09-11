package model

import "github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/valueobject"

// ImpactedRepository is one repository a blast-radius traversal reached,
// together with the path that exposes it.
type ImpactedRepository struct {
	Repository Repository
	Author     Author
	ViaPackage valueobject.PackageRef // the vulnerable library that was reached
	Depth      int                    // DEPENDS_ON hops from the repository to it
	Direct     bool                   // true when the repository's own manifest names it
	Path       []string               // the chain, nearest first, for display
	// DeclaredVersion is what the manifest nearest the library asks for,
	// AffectedVersions what the advisory says is affected, and Verdict the
	// judgement of one against the other.
	DeclaredVersion  string
	AffectedVersions string
	Verdict          valueobject.ExposureVerdict
}

// BlastRadius answers "who is exposed to this CVE?". VulnerablePackages is
// what the advisory named; Repositories is what actually depends on them.
//
// The two are reported separately on purpose: an empty Repositories list with
// a non-empty VulnerablePackages list means the CVE is understood but nothing
// tracked is exposed, whereas both empty means the CVE has no package linkage
// yet and the question could not be answered at all.
type BlastRadius struct {
	CVEID              string
	VulnerablePackages []valueobject.PackageRef
	Repositories       []ImpactedRepository
}

// TotalRepositories reports how many repositories are exposed.
func (b BlastRadius) TotalRepositories() int { return len(b.Repositories) }

// Linked reports whether the CVE is connected to any library at all. When it
// is false, an empty result means "unknown", not "nothing is affected".
func (b BlastRadius) Linked() bool { return len(b.VulnerablePackages) > 0 }
