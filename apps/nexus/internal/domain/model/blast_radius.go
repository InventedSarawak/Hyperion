package model

import "strings"

// ImpactedRepository is one repository exposed to a vulnerability, and the
// dependency path that exposes it.
type ImpactedRepository struct {
	Owner      string
	Name       string
	URL        string
	AuthorName string
	ViaPackage string
	Depth      int
	Direct     bool
	Path       []string
}

// FullName is the repository's identity, e.g. "vercel/commerce".
func (r ImpactedRepository) FullName() string { return r.Owner + "/" + r.Name }

// Chain renders the dependency path as an arrow-separated line.
func (r ImpactedRepository) Chain() string {
	if len(r.Path) == 0 {
		return r.FullName()
	}
	return strings.Join(r.Path, " → ")
}

// BlastRadius answers "who is exposed to this vulnerability?".
//
// VulnerablePackages and Repositories are reported separately on purpose: an
// empty repository list alongside named packages means "nothing we track is
// exposed", whereas both empty means the question could not be answered at all.
type BlastRadius struct {
	CVEID              string
	VulnerablePackages []string
	Repositories       []ImpactedRepository
}

// Linked reports whether the vulnerability is connected to any library.
func (b BlastRadius) Linked() bool { return len(b.VulnerablePackages) > 0 }
